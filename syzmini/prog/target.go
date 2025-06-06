// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
)

// Target describes target OS/arch pair.
type Target struct {
	OS                string
	Arch              string
	Revision          string // unique hash representing revision of the descriptions
	PtrSize           uint64
	PageSize          uint64
	NumPages          uint64
	DataOffset        uint64
	LittleEndian      bool
	ExecutorUsesShmem bool

	Syscalls  []*Syscall
	Resources []*ResourceDesc
	Consts    []ConstValue
	Flags     []FlagDesc

	// MakeDataMmap creates calls that mmaps target data memory range.
	MakeDataMmap func() []*Call

	// Neutralize neutralizes harmful calls by transforming them into non-harmful ones
	// (e.g. an ioctl that turns off console output is turned into ioctl that turns on output).
	// fixStructure determines whether it's allowed to make structural changes (e.g. add or
	// remove arguments). It is helpful e.g. when we do neutralization while iterating over the
	// arguments.
	Neutralize func(c *Call, fixStructure bool) error

	// AnnotateCall annotates a syscall invocation in C reproducers.
	// The returned string will be placed inside a comment except for the
	// empty string which will omit the comment.
	AnnotateCall func(c ExecCall) string

	// SpecialTypes allows target to do custom generation/mutation for some struct's and union's.
	// Map key is struct/union name for which custom generation/mutation is required.
	// Map value is custom generation/mutation function that will be called
	// for the corresponding type. g is helper object that allows generate random numbers,
	// allocate memory, etc. typ is the struct/union type. old is the old value of the struct/union
	// for mutation, or nil for generation. The function returns a new value of the struct/union,
	// and optionally any calls that need to be inserted before the arg reference.
	SpecialTypes map[string]func(g *Gen, typ Type, dir Dir, old Arg) (Arg, []*Call)

	// Resources that play auxiliary role, but widely used throughout all syscalls (e.g. pid/uid).
	AuxResources map[string]bool

	// Additional special invalid pointer values besides NULL to use.
	SpecialPointers []uint64

	// Special file name length that can provoke bugs (e.g. PATH_MAX).
	SpecialFileLenghts []int

	// Filled by prog package:
	SyscallMap map[string]*Syscall
	ConstMap   map[string]uint64
	FlagsMap   map[string][]string

	init        sync.Once
	initArch    func(target *Target)
	types       []Type
	resourceMap map[string]*ResourceDesc
	// Maps resource name to a list of calls that can create the resource.
	resourceCtors map[string][]ResourceCtor
	any           anyTypes

	// The default ChoiceTable is used only by tests and utilities, so we initialize it lazily.
	defaultOnce        sync.Once
	defaultChoiceTable *ChoiceTable

	// consume code
	InfluenceMatrix [][]uint8
}

const maxSpecialPointers = 16

var targets = make(map[string]*Target)

func RegisterTarget(target *Target, types []Type, initArch func(target *Target)) {
	key := target.OS + "/" + target.Arch
	if targets[key] != nil {
		panic(fmt.Sprintf("duplicate target %v", key))
	}
	target.initArch = initArch
	target.types = types
	targets[key] = target
}

func GetTarget(OS, arch string) (*Target, error) {
	if OS == "android" {
		OS = "linux"
	}
	key := OS + "/" + arch
	target := targets[key]
	if target == nil {
		var supported []string
		for _, t := range targets {
			supported = append(supported, fmt.Sprintf("%v/%v", t.OS, t.Arch))
		}
		sort.Strings(supported)
		return nil, fmt.Errorf("unknown target: %v (supported: %v)", key, supported)
	}
	target.init.Do(target.lazyInit)
	return target, nil
}

func AllTargets() []*Target {
	var res []*Target
	for _, target := range targets {
		target.init.Do(target.lazyInit)
		res = append(res, target)
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].OS != res[j].OS {
			return res[i].OS < res[j].OS
		}
		return res[i].Arch < res[j].Arch
	})
	return res
}

func (target *Target) lazyInit() {
	target.Neutralize = func(c *Call, fixStructure bool) error { return nil }
	target.AnnotateCall = func(c ExecCall) string { return "" }
	target.initTarget()
	target.initArch(target)
	// Give these 2 known addresses fixed positions and prepend target-specific ones at the end.
	target.SpecialPointers = append([]uint64{
		0x0000000000000000, // NULL pointer (keep this first because code uses special index=0 as NULL)
		0xffffffffffffffff, // unmapped kernel address (keep second because serialized value will match actual pointer value)
		0x9999999999999999, // non-canonical address
	}, target.SpecialPointers...)
	if len(target.SpecialPointers) > maxSpecialPointers {
		panic("too many special pointers")
	}
	if len(target.SpecialFileLenghts) == 0 {
		// Just some common lengths that can be used as PATH_MAX/MAX_NAME.
		target.SpecialFileLenghts = []int{256, 512, 4096}
	}
	for _, ln := range target.SpecialFileLenghts {
		if ln <= 0 || ln >= memAllocMaxMem {
			panic(fmt.Sprintf("bad special file length %v", ln))
		}
	}
	// These are used only during lazyInit.
	target.types = nil
}

func (target *Target) initTarget() {
	checkMaxCallID(len(target.Syscalls) - 1)
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}

	target.resourceMap = restoreLinks(target.Syscalls, target.Resources, target.types)
	target.initAnyTypes()

	target.SyscallMap = make(map[string]*Syscall)
	for i, c := range target.Syscalls {
		c.ID = i
		target.SyscallMap[c.Name] = c
	}

	target.FlagsMap = make(map[string][]string)
	for _, c := range target.Flags {
		target.FlagsMap[c.Name] = c.Values
	}

	target.populateResourceCtors()
	target.resourceCtors = make(map[string][]ResourceCtor)
	for _, res := range target.Resources {
		target.resourceCtors[res.Name] = target.calcResourceCtors(res, false)
	}
}

func (target *Target) GetConst(name string) uint64 {
	v, ok := target.ConstMap[name]
	if !ok {
		panic(fmt.Sprintf("const %v is not defined for %v/%v", name, target.OS, target.Arch))
	}
	return v
}

func (target *Target) sanitize(c *Call, fix bool) error {
	// For now, even though we accept the fix argument, it does not have the full effect.
	// It de facto only denies structural changes, e.g. deletions of arguments.
	// TODO: rewrite the corresponding sys/*/init.go code.
	return target.Neutralize(c, fix)
}

func RestoreLinks(syscalls []*Syscall, resources []*ResourceDesc, types []Type) {
	restoreLinks(syscalls, resources, types)
}

var (
	typeRefMu sync.Mutex
	typeRefs  atomic.Value // []Type
)

func restoreLinks(syscalls []*Syscall, resources []*ResourceDesc, types []Type) map[string]*ResourceDesc {
	typeRefMu.Lock()
	defer typeRefMu.Unlock()
	refs := []Type{nil}
	if old := typeRefs.Load(); old != nil {
		refs = old.([]Type)
	}
	for _, typ := range types {
		typ.setRef(Ref(len(refs)))
		refs = append(refs, typ)
	}
	typeRefs.Store(refs)

	resourceMap := make(map[string]*ResourceDesc)
	for _, res := range resources {
		resourceMap[res.Name] = res
	}

	ForeachType(syscalls, func(typ Type, ctx *TypeCtx) {
		if ref, ok := typ.(Ref); ok {
			typ = types[ref]
			*ctx.Ptr = typ
		}
		switch t := typ.(type) {
		case *ResourceType:
			t.Desc = resourceMap[t.TypeName]
			if t.Desc == nil {
				panic("no resource desc")
			}
		}
	})
	return resourceMap
}

func (target *Target) DefaultChoiceTable() *ChoiceTable {
	target.defaultOnce.Do(func() {
		target.defaultChoiceTable = target.BuildChoiceTable(nil, nil)
	})
	return target.defaultChoiceTable
}

func (target *Target) GetGlobs() map[string]bool {
	globs := make(map[string]bool)
	ForeachType(target.Syscalls, func(typ Type, ctx *TypeCtx) {
		switch a := typ.(type) {
		case *BufferType:
			if a.Kind == BufferGlob {
				globs[a.SubKind] = true
			}
		}
	})
	return globs
}

func (target *Target) UpdateGlobs(globFiles map[string][]string) {
	ForeachType(target.Syscalls, func(typ Type, ctx *TypeCtx) {
		switch a := typ.(type) {
		case *BufferType:
			if a.Kind == BufferGlob {
				a.Values = globFiles[a.SubKind]
			}
		}
	})
}

type Gen struct {
	r *randGen
	s *state
}

func (g *Gen) Target() *Target {
	return g.r.target
}

func (g *Gen) Rand() *rand.Rand {
	return g.r.Rand
}

func (g *Gen) NOutOf(n, outOf int) bool {
	return g.r.nOutOf(n, outOf)
}

func (g *Gen) Alloc(ptrType Type, dir Dir, data Arg) (Arg, []*Call) {
	return g.r.allocAddr(g.s, ptrType, dir, data.Size(), data), nil
}

func (g *Gen) GenerateArg(typ Type, dir Dir, pcalls *[]*Call) Arg {
	return g.generateArg(typ, dir, pcalls, false)
}

func (g *Gen) GenerateSpecialArg(typ Type, dir Dir, pcalls *[]*Call) Arg {
	return g.generateArg(typ, dir, pcalls, true)
}

func (g *Gen) generateArg(typ Type, dir Dir, pcalls *[]*Call, ignoreSpecial bool) Arg {
	arg, calls := g.r.generateArgImpl(g.s, typ, dir, ignoreSpecial)
	*pcalls = append(*pcalls, calls...)
	g.r.target.assignSizesArray([]Arg{arg}, []Field{{Name: "", Type: arg.Type()}}, nil)
	return arg
}

func (g *Gen) MutateArg(arg0 Arg) (calls []*Call) {
	updateSizes := true
	for stop := false; !stop; stop = g.r.oneOf(3) {
		ma := &mutationArgs{target: g.r.target, ignoreSpecial: true}
		ForeachSubArg(arg0, ma.collectArg)
		if len(ma.args) == 0 {
			// TODO(dvyukov): probably need to return this condition
			// and updateSizes to caller so that Mutate can act accordingly.
			return
		}
		arg, ctx := ma.chooseArg(g.r.Rand)
		newCalls, ok := g.r.target.mutateArg(g.r, g.s, arg, ctx, &updateSizes)
		if !ok {
			continue
		}
		calls = append(calls, newCalls...)
	}
	return calls
}

type Builder struct {
	target *Target
	ma     *memAlloc
	p      *Prog
}

func MakeProgGen(target *Target) *Builder {
	return &Builder{
		target: target,
		ma:     newMemAlloc(target.NumPages * target.PageSize),
		p: &Prog{
			Target: target,
		},
	}
}

func (pg *Builder) Append(c *Call) error {
	pg.target.assignSizesCall(c)
	pg.target.sanitize(c, true)
	pg.p.Calls = append(pg.p.Calls, c)
	return nil
}

func (pg *Builder) Allocate(size, alignment uint64) uint64 {
	return pg.ma.alloc(nil, size, alignment)
}

func (pg *Builder) AllocateVMA(npages uint64) uint64 {
	return pg.ma.alloc(nil, npages*pg.target.PageSize, pg.target.PageSize)
}

func (pg *Builder) Finalize() (*Prog, error) {
	if err := pg.p.validate(); err != nil {
		return nil, err
	}
	if _, err := pg.p.SerializeForExec(make([]byte, ExecBufferSize)); err != nil {
		return nil, err
	}
	p := pg.p
	pg.p = nil
	return p, nil
}

// consume code
func (target *Target) AnalyzeStaticInfluence() {
	type_uses := target.calcTypeUsage()
	fmt.Printf("length of type:%v\n", len(type_uses))
	target.InfluenceMatrix = make([][]uint8, len(target.Syscalls))
	for i := range target.InfluenceMatrix {
		target.InfluenceMatrix[i] = make([]uint8, len(target.Syscalls))
	}

	count := 0
	for _, callid_dir := range type_uses {
		dirIn_ids := []int{}
		dirOut_ids := []int{}
		for callid, dir := range callid_dir {
			if dir == DirIn || dir == DirInOut {
				dirIn_ids = append(dirIn_ids, callid)
			}
			if dir == DirOut {
				dirOut_ids = append(dirOut_ids, callid)
			}
		}
		if len(dirOut_ids) > 0 {
			for _, call_id_src := range dirOut_ids {
				for _, call_id_dest := range dirIn_ids {
					if call_id_src != call_id_dest {
						// if target.InfluenceMatrix[call_id_src][call_id_dest] != 1 {
						// 	count++
						// }
						target.InfluenceMatrix[call_id_src][call_id_dest] = 1

						// fmt.Printf("\n%v\n%v\n", target.Syscalls[call_id_src], target.Syscalls[call_id_dest])
					}
				}
			}
		}
		// fmt.Printf("%v,%v,%v\n",type_name,len(dirOut_ids),len(dirIn_ids))
	}
	fmt.Printf("Syzkaller call length %v\n", len(target.Syscalls))
	fmt.Printf("The number of static influence pair:%v\n", count)
}

func (target *Target) calcTypeUsage() map[string]map[int]Dir {
	type_uses := make(map[string]map[int]Dir)
	ForeachType(target.Syscalls, func(t Type, ctx *TypeCtx) {
		c := ctx.Meta
		switch a := t.(type) {
		case *ResourceType:
			if _, ok := type_uses[a.Name()]; !ok {
				resName := t.Name()
				type_uses[resName] = make(map[int]Dir)
				type_uses[resName][c.ID] = ctx.Dir
			} else {
				type_uses[t.Name()][c.ID] = ctx.Dir
			}
		case *PtrType:
		case *BufferType:
		case *VmaType:
		case *IntType:
		}
	})
	return type_uses
}
func noteTypeUses(uses map[string]map[int]Dir, c *Syscall, dir Dir, str string, args ...interface{}) {
	id := fmt.Sprintf(str, args...)
	// id := fmt.Sprintf(str, ref)
	if uses[id] == nil {
		uses[id] = make(map[int]Dir)
	}
	uses[id][c.ID] = dir
}
