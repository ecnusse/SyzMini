// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"reflect"
)

// Minimize minimizes program p into an equivalent program using the equivalence
// predicate pred. It iteratively generates simpler programs and asks pred
// whether it is equal to the original program or not. If it is equivalent then
// the simplification attempt is committed and the process continues.
func Minimize(p0 *Prog, callIndex0 int, crash bool, pred0 func(*Prog, int, int) bool) (*Prog, int) {
	pred := func(p *Prog, callIndex int, minimize_type_flag int) bool {
		p.sanitizeFix()
		p.debugValidate()
		return pred0(p, callIndex, minimize_type_flag)
	}
	name0 := ""
	if callIndex0 != -1 {
		if callIndex0 < 0 || callIndex0 >= len(p0.Calls) {
			panic("bad call index")
		}
		name0 = p0.Calls[callIndex0].Meta.Name
	}

	// Try to remove all calls except the last one one-by-one.
	p0, callIndex0 = removeCalls(p0, callIndex0, crash, pred)

	// Try to reset all call props to their default values.
	// p0 = resetCallProps(p0, callIndex0, pred)

	// Try to minimize individual calls.
	for i := 0; i < len(p0.Calls); i++ {
		if p0.Calls[i].Meta.Attrs.NoMinimize {
			continue
		}
		ctx := &minimizeArgsCtx{
			target:     p0.Target,
			p0:         &p0,
			callIndex0: callIndex0,
			crash:      crash,
			pred:       pred,
			triedPaths: make(map[string]bool),
		}
	again:
		ctx.p = p0.Clone()
		ctx.call = ctx.p.Calls[i]
		for j, field := range ctx.call.Meta.Args {
			if ctx.do(ctx.call.Args[j], field.Name, "") {
				goto again
			}
		}
		// p0 = minimizeCallProps(p0, i, callIndex0, pred)
	}

	if callIndex0 != -1 {
		if callIndex0 < 0 || callIndex0 >= len(p0.Calls) || name0 != p0.Calls[callIndex0].Meta.Name {
			panic(fmt.Sprintf("bad call index after minimization: ncalls=%v index=%v call=%v/%v",
				len(p0.Calls), callIndex0, name0, p0.Calls[callIndex0].Meta.Name))
		}
	}
	return p0, callIndex0
}

func removeCalls(p0 *Prog, callIndex0 int, crash bool, pred func(*Prog, int, int) bool) (*Prog, int) {
	// call-level optimization
	remove_post_ids := []int{}
	remove_front_ids := []int{}
	queue := NewIntQueue()
	queue_map := make(map[int]bool)
	influence_map := make(map[int]bool)
	if callIndex0 >= 0 && callIndex0+2 < len(p0.Calls) {
		for i := callIndex0 + 1; i < len(p0.Calls); i++ {
			remove_post_ids = append(remove_post_ids, i)
		}
	}

	for i := callIndex0 - 1; i >= 0; i-- {
		if p0.Target.InfluenceMatrix[p0.Calls[i].Meta.ID][p0.Calls[callIndex0].Meta.ID] == 1 { // be influenced calls
			queue.Enqueue(i)
			influence_map[i] = true
			queue_map[i] = true

			for queue.Length() > 0 {
				id, _ := queue.Dequeue()
				for j := id - 1; j >= 0; j-- {
					if p0.Target.InfluenceMatrix[p0.Calls[j].Meta.ID][p0.Calls[id].Meta.ID] == 1 {
						influence_map[j] = true
						if queue_map[j] == false {
							queue.Enqueue(j)
						}
					}
				}
			}
		}
	}
	for i := 0; i < callIndex0; i++ {
		if influence_map[i] == false {
			remove_front_ids = append(remove_front_ids, i)
		}
	}

	// remove post calls
	if len(remove_post_ids) > 0 {
		p := p0.Clone()
		for index, _ := range remove_post_ids { //remove back
			p.RemoveCall(remove_post_ids[len(remove_post_ids)-1-index]) //from back to front
		}

		if pred(p, callIndex0, 1) {
			p0 = p

		}
	}
	// // remove front calls
	// if len(remove_front_ids) > 0 {
	// 	p := p0.Clone()
	// 	for index, _ := range remove_front_ids { //remove front
	// 		p.RemoveCall(remove_front_ids[len(remove_front_ids)-1-index]) //from back to front
	// 	}
	// 	callIndex := callIndex0 - len(remove_front_ids)
	// 	if pred(p, callIndex, 1) {
	// 		p0 = p
	// 		callIndex0 = callIndex
	// 	}
	// }

	if callIndex0 != -1 {
		p0, callIndex0 = removeUnrelatedCalls(p0, callIndex0, pred)
	}

	for i := len(p0.Calls) - 1; i >= 0; i-- {
		if i == callIndex0 {
			continue
		}
		callIndex := callIndex0
		if i < callIndex {
			callIndex--
		}
		p := p0.Clone()
		p.RemoveCall(i)
		if !pred(p, callIndex, 1) {
			continue
		}
		p0 = p
		callIndex0 = callIndex
	}
	return p0, callIndex0
}

func resetCallProps(p0 *Prog, callIndex0 int, pred func(*Prog, int, int) bool) *Prog {
	// Try to reset all call props to their default values.
	// This should be reasonable for many progs.
	p := p0.Clone()
	anyDifferent := false
	for idx := range p.Calls {
		if !reflect.DeepEqual(p.Calls[idx].Props, CallProps{}) {
			p.Calls[idx].Props = CallProps{}
			anyDifferent = true
		}
	}
	if anyDifferent && pred(p, callIndex0, 1) {
		return p
	}
	return p0
}

func minimizeCallProps(p0 *Prog, callIndex, callIndex0 int, pred func(*Prog, int, int) bool) *Prog {
	props := p0.Calls[callIndex].Props

	// Try to drop fault injection.
	if props.FailNth > 0 {
		p := p0.Clone()
		p.Calls[callIndex].Props.FailNth = 0
		if pred(p, callIndex0, 1) {
			p0 = p
		}
	}

	// Try to drop async.
	if props.Async {
		p := p0.Clone()
		p.Calls[callIndex].Props.Async = false
		if pred(p, callIndex0, 1) {
			p0 = p
		}
	}

	// Try to drop rerun.
	if props.Rerun > 0 {
		p := p0.Clone()
		p.Calls[callIndex].Props.Rerun = 0
		if pred(p, callIndex0, 1) {
			p0 = p
		}
	}

	return p0
}

type minimizeArgsCtx struct {
	target     *Target
	p0         **Prog
	p          *Prog
	call       *Call
	callIndex0 int
	crash      bool
	pred       func(*Prog, int, int) bool
	triedPaths map[string]bool
}

func (ctx *minimizeArgsCtx) do(arg Arg, field, path string) bool {
	path += fmt.Sprintf("-%v", field)
	if ctx.triedPaths[path] {
		return false
	}
	// p0 := *ctx.p0
	if arg.Type().minimize(ctx, arg, path) {
		return true
	}
	// if *ctx.p0 == ctx.p {
	// 	// If minimize committed a new program, it must return true.
	// 	// Otherwise *ctx.p0 and ctx.p will point to the same program
	// 	// and any temp mutations to ctx.p will unintentionally affect ctx.p0.
	// 	panic("shared program committed")
	// }
	// if *ctx.p0 != p0 {
	// 	// New program was committed, but we did not start iteration anew.
	// 	// This means we are iterating over a stale tree and any changes won't be visible.
	// 	panic("iterating over stale program")
	// }
	ctx.triedPaths[path] = true
	return false
}

func (typ *TypeCommon) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return false
}

func (typ *StructType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*GroupArg)
	for i, innerArg := range a.Inner {
		if ctx.do(innerArg, typ.Fields[i].Name, path) {
			return true
		}
	}
	return false
}

func (typ *UnionType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*UnionArg)
	return ctx.do(a.Option, typ.Fields[a.Index].Name, path)
}

func (typ *PtrType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*PointerArg)
	if a.Res == nil {
		return false
	}
	if path1 := path + ">"; !ctx.triedPaths[path1] {
		// source code
		removeArg(a.Res)
		replaceArg(a, MakeSpecialPointerArg(a.Type(), a.Dir(), 0))
		ctx.target.assignSizesCall(ctx.call)
		if ctx.pred(ctx.p, ctx.callIndex0, 2) {
			*ctx.p0 = ctx.p
		}
		ctx.triedPaths[path1] = true
		return true
	}
	return ctx.do(a.Res, "", path)
}

func (typ *ArrayType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*GroupArg)

	// arg optimize
	if allPath := path + "-all"; len(a.Inner) >= 3 && typ.RangeBegin == 0 && !ctx.triedPaths[allPath] {
		ctx.triedPaths[allPath] = true
		for _, elem := range a.Inner {
			removeArg(elem)
		}
		a.Inner = nil
		ctx.target.assignSizesCall(ctx.call)
		if ctx.pred(ctx.p, ctx.callIndex0, 2) {
			*ctx.p0 = ctx.p
		}
		return true
	}

	for i := len(a.Inner) - 1; i >= 0; i-- {
		elem := a.Inner[i]
		elemPath := fmt.Sprintf("%v-%v", path, i)
		// Try to remove individual elements one-by-one.
		if !ctx.crash && !ctx.triedPaths[elemPath] &&
			(typ.Kind == ArrayRandLen ||
				typ.Kind == ArrayRangeLen && uint64(len(a.Inner)) > typ.RangeBegin) {
			ctx.triedPaths[elemPath] = true
			copy(a.Inner[i:], a.Inner[i+1:])
			a.Inner = a.Inner[:len(a.Inner)-1]
			removeArg(elem)
			ctx.target.assignSizesCall(ctx.call)
			if ctx.pred(ctx.p, ctx.callIndex0, 2) {
				*ctx.p0 = ctx.p
			}
			return true
		}
		if ctx.do(elem, "", elemPath) {
			return true
		}
	}
	return false
}

func (typ *IntType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return minimizeInt(ctx, arg, path)
}

func (typ *FlagsType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return minimizeInt(ctx, arg, path)
}

func (typ *ProcType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if !typ.Optional() {
		// Default value for ProcType is 0 (same for all PID's).
		// Usually 0 either does not make sense at all or make different PIDs collide
		// (since we use ProcType to separate value ranges for different PIDs).
		// So don't change ProcType to 0 unless the type is explicitly marked as opt
		// (in that case we will also generate 0 anyway).
		return false
	}
	return minimizeInt(ctx, arg, path)
}

func minimizeInt(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	// // TODO: try to reset bits in ints
	// TODO: try to set separate flags
	if ctx.crash {
		return false
	}
	a := arg.(*ConstArg)
	def := arg.Type().DefaultArg(arg.Dir()).(*ConstArg)
	if a.Val == def.Val {
		return false
	}
	v0 := a.Val
	a.Val = def.Val

	// By mutating an integer, we risk violating conditional fields.
	// If the fields are patched, the minimization process must be restarted.
	patched := ctx.call.setDefaultConditions(ctx.p.Target)
	if ctx.pred(ctx.p, ctx.callIndex0, 2) {
		*ctx.p0 = ctx.p
		ctx.triedPaths[path] = true
		return true
	}
	a.Val = v0
	if patched {
		// No sense to return here.
		ctx.triedPaths[path] = true
	}
	return patched
}

func (typ *ResourceType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if ctx.crash {
		return false
	}
	a := arg.(*ResultArg)
	if a.Res == nil {
		return false
	}
	r0 := a.Res
	delete(a.Res.uses, a)
	a.Res, a.Val = nil, typ.Default()
	if ctx.pred(ctx.p, ctx.callIndex0, 2) {
		*ctx.p0 = ctx.p
	} else {
		a.Res, a.Val = r0, 0
		a.Res.uses[a] = true
	}
	ctx.triedPaths[path] = true
	return true
}

func (typ *BufferType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if arg.Dir() == DirOut {
		return false
	}
	if typ.IsCompressed() {
		panic(fmt.Sprintf("minimizing `no_minimize` call %v", ctx.call.Meta.Name))
	}
	a := arg.(*DataArg)
	switch typ.Kind {
	case BufferBlobRand, BufferBlobRange:
		// TODO: try to set individual bytes to 0
		len0 := len(a.Data())
		minLen := int(typ.RangeBegin)
		for step := len(a.Data()) - minLen; len(a.Data()) > minLen && step > 0; {
			if len(a.Data())-step >= minLen {
				a.data = a.Data()[:len(a.Data())-step]
				ctx.target.assignSizesCall(ctx.call)
				if ctx.pred(ctx.p, ctx.callIndex0, 2) {
					continue
				}
				a.data = a.Data()[:len(a.Data())+step]
				ctx.target.assignSizesCall(ctx.call)
			}
			step /= 2
			if ctx.crash {
				break
			}
		}
		if len(a.Data()) != len0 {
			*ctx.p0 = ctx.p
			ctx.triedPaths[path] = true
			return true
		}
	case BufferFilename:
		// Try to undo target.SpecialFileLenghts mutation
		// and reduce file name length.
		if !typ.Varlen() {
			return false
		}
		data0 := append([]byte{}, a.Data()...)
		a.data = bytes.TrimRight(a.Data(), specialFileLenPad+"\x00")
		if !typ.NoZ {
			a.data = append(a.data, 0)
		}
		if bytes.Equal(a.data, data0) {
			return false
		}
		ctx.target.assignSizesCall(ctx.call)
		if ctx.pred(ctx.p, ctx.callIndex0, 2) {
			*ctx.p0 = ctx.p
		}
		ctx.triedPaths[path] = true
		return true
	}
	return false
}

type IntQueue struct {
	items []int
}

func NewIntQueue() *IntQueue {
	return &IntQueue{
		items: []int{},
	}
}

func (q *IntQueue) Enqueue(item int) {
	q.items = append(q.items, item)
}

func (q *IntQueue) Dequeue() (int, bool) {
	if len(q.items) == 0 {
	}
	item := q.items[0]
	q.items = q.items[1:]
	return item, true
}

func (q *IntQueue) Length() int {
	return len(q.items)
}

func (q *IntQueue) IsEmpty() bool {
	return len(q.items) == 0
}

// removeUnrelatedCalls tries to remove all "unrelated" calls at once.
// Unrelated calls are the calls that don't use any resources/files from
// the transitive closure of the resources/files used by the target call.
// This may significantly reduce large generated programs in a single step.
func removeUnrelatedCalls(p0 *Prog, callIndex0 int, pred func(*Prog, int, int) bool) (*Prog, int) {
	keepCalls := relatedCalls(p0, callIndex0)
	if len(p0.Calls)-len(keepCalls) < 3 {
		return p0, callIndex0
	}
	p, callIndex := p0.Clone(), callIndex0
	for i := len(p0.Calls) - 1; i >= 0; i-- {
		if keepCalls[i] {
			continue
		}
		p.RemoveCall(i)
		if i < callIndex {
			callIndex--
		}
	}
	if !pred(p, callIndex, 1) {
		return p0, callIndex0
	}
	return p, callIndex
}

func relatedCalls(p0 *Prog, callIndex0 int) map[int]bool {
	keepCalls := map[int]bool{callIndex0: true}
	used := uses(p0.Calls[callIndex0])
	for {
		n := len(used)
		for i, call := range p0.Calls {
			if keepCalls[i] {
				continue
			}
			used1 := uses(call)
			if intersects(used, used1) {
				keepCalls[i] = true
				for what := range used1 {
					used[what] = true
				}
			}
		}
		if n == len(used) {
			return keepCalls
		}
	}
}

func uses(call *Call) map[any]bool {
	used := make(map[any]bool)
	ForeachArg(call, func(arg Arg, _ *ArgCtx) {
		switch typ := arg.Type().(type) {
		case *ResourceType:
			a := arg.(*ResultArg)
			used[a] = true
			if a.Res != nil {
				used[a.Res] = true
			}
			for use := range a.uses {
				used[use] = true
			}
		case *BufferType:
			a := arg.(*DataArg)
			if a.Dir() != DirOut && typ.Kind == BufferFilename {
				val := string(bytes.TrimRight(a.Data(), "\x00"))
				used[val] = true
			}
		}
	})
	return used
}

func intersects(list, list1 map[any]bool) bool {
	for what := range list1 {
		if list[what] {
			return true
		}
	}
	return false
}
