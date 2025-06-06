// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// execprog executes a single program or a set of programs
// and optionally prints information about execution.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagOS        = flag.String("os", runtime.GOOS, "target os")
	flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
	flagCoverFile = flag.String("coverfile", "", "write coverage to the file")
	flagRepeat    = flag.Int("repeat", 1, "repeat execution that many times (0 for infinite loop)")
	flagProcs     = flag.Int("procs", 2*runtime.NumCPU(), "number of parallel processes to execute programs")
	flagOutput    = flag.Bool("output", false, "write programs and results to stdout")
	flagHints     = flag.Bool("hints", false, "do a hints-generation run")
	flagEnable    = flag.String("enable", "none", "enable only listed additional features")
	flagDisable   = flag.String("disable", "none", "enable all additional features except listed")
	// The following flag is only kept to let syzkaller remain compatible with older execprog versions.
	// In order to test incoming patches or perform bug bisection, syz-ci must use the exact syzkaller
	// version that detected the bug (as descriptions and syntax could've already been changed), and
	// therefore it must be able to invoke older versions of syz-execprog.
	// Unfortunately there's no clean way to drop that flag from newer versions of syz-execprog. If it
	// were false by default, it would be easy - we could modify `instance.ExecprogCmd` only to pass it
	// when it's true - which would never be the case in the newer versions (this is how we got rid of
	// fault injection args). But the collide flag was true by default, so it must be passed by value
	// (-collide=%v). The least kludgy solution is to silently accept this flag also in the newer versions
	// of syzkaller, but do not process it, as there's no such functionality anymore.
	// Note, however, that we do not have to do the same for `syz-prog2c`, as `collide` was there false
	// by default.
	flagCollide = flag.Bool("collide", false, "(DEPRECATED) collide syscalls to provoke data races")

	flagProgramDirPath      = flag.String("programdir", "", "the dir path for program")
	flagOutPath             = flag.String("outpath", "", "the file for saving result path")
	flagStartIdx            = flag.Int("startidx", -1, "start index")
	flagInfluenceProportion = flag.Int("influenceproportion", 100, "influence Proportion")
)
var file_path_ary []string
var call_index_ary []int
var index_map = make(map[int]bool)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: execprog [flags] file-with-programs-or-corpus.db+\n")
		flag.PrintDefaults()
		csource.PrintAvailableFeaturesFlags()
	}
	defer tool.Init()()
	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	featuresFlags, err := csource.ParseFeaturesFlags(*flagEnable, *flagDisable, true)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// read
	file, err := os.Open(*flagOutPath)
	if err != nil {
		fmt.Println("erroe:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "idx") || strings.Contains(line, ",") {
			continue
		} else {
			trimmedLine := strings.TrimSpace(line)
			index, _ := strconv.Atoi(trimmedLine)
			fmt.Printf("%v,", index)
			index_map[index] = true
		}
	}

	if *flagProgramDirPath != "" {
		files, err := os.ReadDir(*flagProgramDirPath)
		if err != nil {
			fmt.Printf("Error:\n%v\n", *flagProgramDirPath, err)
			return
		}
		for _, file := range files {
			if !file.IsDir() {
				file_path_ary = append(file_path_ary, *flagProgramDirPath+"/"+file.Name())
				call_index, _ := strconv.Atoi(strings.Split(file.Name(), "_")[1])
				call_index_ary = append(call_index_ary, call_index)
			}
		}
		fmt.Printf("array_length:%v,%v\n%v\n", len(file_path_ary), len(call_index_ary), call_index_ary)
	}
	fmt.Printf("array_length:%v,%v\n%v\n", len(file_path_ary), len(call_index_ary), call_index_ary)

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}
	// consume code
	target.AnalyzeStaticInfluence()
	if *flagInfluenceProportion != 0 && *flagInfluenceProportion != 100 {
		var onesCoords []struct{ row, col int }
		for i := range target.InfluenceMatrix {
			for j := range target.InfluenceMatrix[i] {
				if target.InfluenceMatrix[i][j] == 1 {
					onesCoords = append(onesCoords, struct{ row, col int }{i, j})
				}
			}
		}
		numToZero := len(onesCoords) / 100 * (100 - *flagInfluenceProportion)
		if numToZero == 0 {
			return
		}
		rand.Seed(time.Now().UnixNano())
		for _, idx := range rand.Perm(len(onesCoords))[:numToZero] {
			coord := onesCoords[idx]
			target.InfluenceMatrix[coord.row][coord.col] = 0
		}
	}

	count := 0
	for i := 0; i < len(target.InfluenceMatrix); i++ {
		for j := 0; j < len(target.InfluenceMatrix); j++ {
			if target.InfluenceMatrix[i][j] == 1 {
				count++
			}
		}
	}
	fmt.Printf("after influence_proportion:%v,%v\n", count, *flagInfluenceProportion)

	progs := loadPrograms_comsume(target)
	if len(progs) == 0 {
		return
	}
	features, err := host.Check(target)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if *flagOutput {
		for _, feat := range features.Supported() {
			log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
		}
	}
	if *flagCollide {
		log.Logf(0, "note: setting -collide to true is deprecated now and has no effect")
	}
	config, execOpts := createConfig(target, features, featuresFlags)
	if err = host.Setup(target, features, featuresFlags, config.Executor); err != nil {
		log.Fatal(err)
	}
	var gateCallback func()
	if features[host.FeatureLeak].Enabled {
		gateCallback = func() {
			output, err := osutil.RunCmd(10*time.Minute, "", config.Executor, "leak")
			if err != nil {
				os.Stdout.Write(output)
				os.Exit(1)
			}
		}
	}
	sysTarget := targets.Get(*flagOS, *flagArch)
	upperBase := getKernelUpperBase(sysTarget)
	ctx := &Context{
		progs:     progs,
		config:    config,
		execOpts:  execOpts,
		gate:      ipc.NewGate(2**flagProcs, gateCallback),
		shutdown:  make(chan struct{}),
		repeat:    *flagRepeat,
		target:    sysTarget,
		upperBase: upperBase,
	}
	var wg sync.WaitGroup
	wg.Add(*flagProcs)
	for p := 0; p < *flagProcs; p++ {
		pid := p
		go func() {
			defer wg.Done()
			ctx.run(pid)
		}()
	}
	osutil.HandleInterrupts(ctx.shutdown)
	wg.Wait()
}

type Context struct {
	progs     []*prog.Prog
	config    *ipc.Config
	execOpts  *ipc.ExecOpts
	gate      *ipc.Gate
	shutdown  chan struct{}
	logMu     sync.Mutex
	posMu     sync.Mutex
	repeat    int
	pos       int
	lastPrint time.Time
	target    *targets.Target
	upperBase uint32
}

func (ctx *Context) run(pid int) {
	env, err := ipc.MakeEnv(ctx.config, pid)
	if err != nil {
		log.Fatalf("failed to create ipc env: %v", err)
	}
	defer env.Close()
	for {
		select {
		case <-ctx.shutdown:
			return
		default:
		}
		idx := ctx.getProgramIndex()
		if index_map[idx] == true {
			fmt.Println("skip idx")
			continue
		}
		if ctx.repeat > 0 && idx >= len(ctx.progs)*ctx.repeat {
			return
		}
		entry := ctx.progs[idx%len(ctx.progs)]

		// fmt.Printf("%d\n%s\n\n", idx, entry.Serialize())
		fmt.Printf("now is executed:%d\n", idx)
		// consume code: execute minimize and record minimize count
		info_old := ctx.execute_consume(pid, env, entry, idx)
		// fmt.Printf("%d,\n%v,\n%v,\n%s\n", idx, file_path_ary[idx], call_index_ary[idx], entry)
		if info_old != nil {
			call_index_hash := prog.GetHash_uint32(info_old.Calls[call_index_ary[idx]].Signal)

			// minimize
			index_map[idx] = true
			out_content := fmt.Sprintf("%v\n", idx) //mark
			AppendToFile(*flagOutPath, out_content)

			minimize_call_count := 0
			minimize_arg_count := 0
			minimize_total_count := 0
			prog.Minimize(entry, call_index_ary[idx], false,
				func(p1 *prog.Prog, call1 int, minimize_type_flag int) bool {
					for i := 0; i < 3; i++ {
						_, info, _, _ := env.Exec(ctx.execOpts, p1)
						minimize_total_count++
						// consume code
						if minimize_type_flag == 1 { // call-level minimization
							minimize_call_count++
						}
						if minimize_type_flag == 2 { //arg-level minimization
							minimize_arg_count++
						}

						if !reexecutionSuccess(info) {
							// The call was not executed or failed.
							continue
						}
						// fmt.Printf("hash info: %v,%v\n", call_index_hash, prog.GetHash_uint32(info.Calls[call1].Signal))
						if prog.GetHash_uint32(info.Calls[call1].Signal) == call_index_hash {
							return true
						}
					}
					return false
				})

			// save minimize_count
			if *flagOutPath != "" {
				out_content := fmt.Sprintf("current idx:idx\n%v\n%v,%v,%v\n", idx, minimize_total_count, minimize_call_count, minimize_arg_count)
				AppendToFile(*flagOutPath, out_content)
			}
		}

	}
}

func (ctx *Context) execute_consume(pid int, env *ipc.Env, p *prog.Prog, progIndex int) *ipc.ProgInfo {
	// Limit concurrency window.
	ticket := ctx.gate.Enter()
	defer ctx.gate.Leave(ticket)

	callOpts := ctx.execOpts
	if *flagOutput {
		ctx.logProgram(pid, p, callOpts)
	}
	// This mimics the syz-fuzzer logic. This is important for reproduction.
	for try := 0; ; try++ {
		output, info, hanged, err := env.Exec(callOpts, p)
		if err != nil && err != prog.ErrExecBufferTooSmall {
			if try > 10 {
				log.Fatalf("executor failed %v times: %v\n%s", try, err, output)
			}
			// Don't print err/output in this case as it may contain "SYZFAIL" and we want to fail yet.
			log.Logf(1, "executor failed, retrying")
			time.Sleep(time.Second)
			continue
		}
		if ctx.config.Flags&ipc.FlagDebug != 0 || err != nil {
			log.Logf(0, "result: hanged=%v err=%v\n\n%s", hanged, err, output)
		}
		if info != nil {
			ctx.printCallResults(info)
			if *flagHints {
				ctx.printHints(p, info)
			}
			if *flagCoverFile != "" {
				covFile := fmt.Sprintf("%s_prog%d", *flagCoverFile, progIndex)
				ctx.dumpCoverage(covFile, info)
			}
		} else {
			log.Logf(1, "RESULT: no calls executed")
		}
		return info
	}
}

func (ctx *Context) execute(pid int, env *ipc.Env, p *prog.Prog, progIndex int) {
	// Limit concurrency window.
	ticket := ctx.gate.Enter()
	defer ctx.gate.Leave(ticket)

	callOpts := ctx.execOpts
	if *flagOutput {
		ctx.logProgram(pid, p, callOpts)
	}
	// This mimics the syz-fuzzer logic. This is important for reproduction.
	for try := 0; ; try++ {
		output, info, hanged, err := env.Exec(callOpts, p)
		if err != nil && err != prog.ErrExecBufferTooSmall {
			if try > 10 {
				log.Fatalf("executor failed %v times: %v\n%s", try, err, output)
			}
			// Don't print err/output in this case as it may contain "SYZFAIL" and we want to fail yet.
			log.Logf(1, "executor failed, retrying")
			time.Sleep(time.Second)
			continue
		}
		if ctx.config.Flags&ipc.FlagDebug != 0 || err != nil {
			log.Logf(0, "result: hanged=%v err=%v\n\n%s", hanged, err, output)
		}
		if info != nil {
			ctx.printCallResults(info)
			if *flagHints {
				ctx.printHints(p, info)
			}
			if *flagCoverFile != "" {
				covFile := fmt.Sprintf("%s_prog%d", *flagCoverFile, progIndex)
				ctx.dumpCoverage(covFile, info)
			}
		} else {
			log.Logf(1, "RESULT: no calls executed")
		}
		break
	}
}

func (ctx *Context) logProgram(pid int, p *prog.Prog, callOpts *ipc.ExecOpts) {
	data := p.Serialize()
	ctx.logMu.Lock()
	log.Logf(0, "executing program %v:\n%s", pid, data)
	ctx.logMu.Unlock()
}

func (ctx *Context) printCallResults(info *ipc.ProgInfo) {
	for i, inf := range info.Calls {
		if inf.Flags&ipc.CallExecuted == 0 {
			continue
		}
		flags := ""
		if inf.Flags&ipc.CallFinished == 0 {
			flags += " unfinished"
		}
		if inf.Flags&ipc.CallBlocked != 0 {
			flags += " blocked"
		}
		if inf.Flags&ipc.CallFaultInjected != 0 {
			flags += " faulted"
		}
		log.Logf(1, "CALL %v: signal %v, coverage %v errno %v%v",
			i, len(inf.Signal), len(inf.Cover), inf.Errno, flags)
	}
}

func (ctx *Context) printHints(p *prog.Prog, info *ipc.ProgInfo) {
	ncomps, ncandidates := 0, 0
	for i := range p.Calls {
		if *flagOutput {
			fmt.Printf("call %v:\n", i)
		}
		comps := info.Calls[i].Comps
		for v, args := range comps {
			ncomps += len(args)
			if *flagOutput {
				fmt.Printf("comp 0x%x:", v)
				for arg := range args {
					fmt.Printf(" 0x%x", arg)
				}
				fmt.Printf("\n")
			}
		}
		p.MutateWithHints(i, comps, func(p *prog.Prog) {
			ncandidates++
			if *flagOutput {
				log.Logf(1, "PROGRAM:\n%s", p.Serialize())
			}
		})
	}
	log.Logf(0, "ncomps=%v ncandidates=%v", ncomps, ncandidates)
}

func getKernelUpperBase(target *targets.Target) uint32 {
	defaultRet := uint32(0xffffffff)
	if target.OS == targets.Linux {
		// Read the first 8 bytes from /proc/kallsyms.
		f, err := os.Open("/proc/kallsyms")
		if err != nil {
			log.Logf(1, "could not get kernel fixup address: %v", err)
			return defaultRet
		}
		defer f.Close()
		data := make([]byte, 8)
		_, err = f.ReadAt(data, 0)
		if err != nil {
			log.Logf(1, "could not get kernel fixup address: %v", err)
			return defaultRet
		}
		value, err := strconv.ParseUint(string(data), 16, 32)
		if err != nil {
			log.Logf(1, "could not get kernel fixup address: %v", err)
			return defaultRet
		}
		return uint32(value)
	}
	return defaultRet
}

func (ctx *Context) dumpCallCoverage(coverFile string, info *ipc.CallInfo) {
	if len(info.Cover) == 0 {
		return
	}
	buf := new(bytes.Buffer)
	for _, pc := range info.Cover {
		fmt.Fprintf(buf, "0x%x\n", backend.PreviousInstructionPC(ctx.target, cover.RestorePC(pc, ctx.upperBase)))
	}
	err := osutil.WriteFile(coverFile, buf.Bytes())
	if err != nil {
		log.Fatalf("failed to write coverage file: %v", err)
	}
}

func (ctx *Context) dumpCoverage(coverFile string, info *ipc.ProgInfo) {
	for i, inf := range info.Calls {
		log.Logf(0, "call #%v: signal %v, coverage %v", i, len(inf.Signal), len(inf.Cover))
		ctx.dumpCallCoverage(fmt.Sprintf("%v.%v", coverFile, i), &inf)
	}
	log.Logf(0, "extra: signal %v, coverage %v", len(info.Extra.Signal), len(info.Extra.Cover))
	ctx.dumpCallCoverage(fmt.Sprintf("%v.extra", coverFile), &info.Extra)
}

func (ctx *Context) getProgramIndex() int {
	ctx.posMu.Lock()
	idx := ctx.pos
	ctx.pos++
	if idx%len(ctx.progs) == 0 && time.Since(ctx.lastPrint) > 5*time.Second {
		log.Logf(0, "executed programs: %v", idx)
		ctx.lastPrint = time.Now()
	}
	ctx.posMu.Unlock()
	return idx
}

func loadPrograms_comsume(target *prog.Target) []*prog.Prog {
	var progs []*prog.Prog
	for _, fn := range file_path_ary {
		if corpus, err := db.Open(fn, false); err == nil {
			for _, rec := range corpus.Records {
				p, err := target.Deserialize(rec.Val, prog.NonStrict)
				if err != nil {
					continue
				}
				progs = append(progs, p)
			}
			continue
		}
		data, err := os.ReadFile(fn)
		if err != nil {
			log.Fatalf("failed to read log file: %v", err)
		}
		for _, entry := range target.ParseLog(data) {
			progs = append(progs, entry.P)
		}
	}
	log.Logf(0, "parsed %v programs", len(progs))
	return progs
}

func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
	var progs []*prog.Prog
	for _, fn := range files {
		if corpus, err := db.Open(fn, false); err == nil {
			for _, rec := range corpus.Records {
				p, err := target.Deserialize(rec.Val, prog.NonStrict)
				if err != nil {
					fmt.Printf("%v\n", err)
					continue
				}
				progs = append(progs, p)
			}
			fmt.Printf("%v\n", err)
			continue
		}
		data, err := os.ReadFile(fn)
		if err != nil {
			log.Fatalf("failed to read log file: %v", err)
		}
		for _, entry := range target.ParseLog(data) {
			progs = append(progs, entry.P)
		}
	}
	log.Logf(0, "parsed %v programs", len(progs))
	return progs
}

func createConfig(target *prog.Target, features *host.Features, featuresFlags csource.Features) (
	*ipc.Config, *ipc.ExecOpts) {
	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if config.Flags&ipc.FlagSignal != 0 {
		execOpts.Flags |= ipc.FlagCollectCover
	}
	if *flagCoverFile != "" {
		config.Flags |= ipc.FlagSignal
		execOpts.Flags |= ipc.FlagCollectCover
		execOpts.Flags &^= ipc.FlagDedupCover
	}
	if *flagHints {
		if execOpts.Flags&ipc.FlagCollectCover != 0 {
			execOpts.Flags ^= ipc.FlagCollectCover
		}
		execOpts.Flags |= ipc.FlagCollectComps
	}
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureDelayKcovMmap].Enabled {
		config.Flags |= ipc.FlagDelayKcovMmap
	}
	if featuresFlags["tun"].Enabled && features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if featuresFlags["net_dev"].Enabled && features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	if featuresFlags["net_reset"].Enabled {
		config.Flags |= ipc.FlagEnableNetReset
	}
	if featuresFlags["cgroups"].Enabled {
		config.Flags |= ipc.FlagEnableCgroups
	}
	if featuresFlags["close_fds"].Enabled {
		config.Flags |= ipc.FlagEnableCloseFds
	}
	if featuresFlags["devlink_pci"].Enabled && features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if featuresFlags["nic_vf"].Enabled && features[host.FeatureNicVF].Enabled {
		config.Flags |= ipc.FlagEnableNicVF
	}
	if featuresFlags["vhci"].Enabled && features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if featuresFlags["wifi"].Enabled && features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
	return config, execOpts
}

func reexecutionSuccess(info *ipc.ProgInfo) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	return true
}
func AppendToFile(filename string, text string) error {
	// 打开文件以追加写入
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("open file error-> %v\n", err)
		return err
	}

	defer file.Close()

	// 写入文本到文件
	_, err = file.WriteString(text)
	return err
}
