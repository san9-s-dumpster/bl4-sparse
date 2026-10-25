import contextlib
import importlib.util
import io
import json
from pathlib import Path
import random
import struct
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT=Path(__file__).resolve().parents[1]/"bl4_sparse.py"
spec=importlib.util.spec_from_file_location("bl4_sparse",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

BS=65536
def cid(value,kind=1):
    return struct.pack("<Q",value)+b"\x00\x00\x00"+bytes([kind])

def fixture(folder,patch,items,block_offsets,cas_blocks):
    stem=f"pakchunk4-Windows_{patch}_P"
    data=bytes((i%251)+1 for i in range(BS*cas_blocks))
    (folder/(stem+".ucas")).write_bytes(data)
    (folder/(stem+".pak")).write_bytes(b"untouched legacy companion")
    header=bytearray(144)
    header[:16]=m.MAGIC
    header[16]=8
    for offset,value in {20:144,24:len(items),28:len(block_offsets),32:12,
                         36:0,40:32,44:BS,48:0,52:1,84:0,96:0}.items():
        struct.pack_into("<I",header,offset,value)
    struct.pack_into("<Q",header,56,patch+1)
    struct.pack_into("<Q",header,88,2**64-1)
    body=b"".join(c for c,a,n in items)
    body+=b"".join(a.to_bytes(5,"big")+n.to_bytes(5,"big") for c,a,n in items)
    body+=b"".join(a.to_bytes(5,"little")+BS.to_bytes(3,"little")+BS.to_bytes(3,"little")+b"\0"
                   for a in block_offsets)
    body+=bytes(24*len(items))
    (folder/(stem+".utoc")).write_bytes(header+body)
    return folder/(stem+".ucas")

class TestIntervals(unittest.TestCase):
    def test_random_subtraction_against_byte_sets(self):
        r=random.Random(20261025)
        for _ in range(1000):
            a=[sorted(r.sample(range(64),2)) for _ in range(8)]
            b=[sorted(r.sample(range(64),2)) for _ in range(8)]
            expected=set().union(*(set(range(x,y)) for x,y in a))-set().union(*(set(range(x,y)) for x,y in b))
            actual=set().union(*(set(range(x,y)) for x,y in m.subtract(a,b)))
            self.assertEqual(expected,actual)

class TestContainer(unittest.TestCase):
    def make(self,folder):
        # Block 0: superseded. Block 1: live. Block 2: shared dead/live.
        # Block 3: no indexed chunks. Block 4: header, never prune.
        # Block 5: dead but physically aliases block 3, so must remain.
        old=fixture(folder,0,[
            (cid(1),0,BS),(cid(2),BS,BS),(cid(3),2*BS,BS//2),
            (cid(4),2*BS+BS//2,BS//2),(cid(5,6),4*BS,BS),
            (cid(6),5*BS,BS)],
            [0,BS,2*BS,3*BS,4*BS,3*BS],5)
        # Replacement values are different: supersession isn't byte equality.
        fixture(folder,1,[(cid(1),0,BS),(cid(3),BS,BS//2),(cid(6),2*BS,BS),
                          (cid(5,6),3*BS,BS)],[0,BS,2*BS,3*BS],4)
        return old

    def test_plan_shared_blocks_and_unknowns(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            folder=Path(temp)
            old=self.make(folder)
            plan=m.audit(folder)
            self.assertEqual(plan["candidate_bytes"],BS)
            self.assertEqual(plan["targets"][0]["ranges"],[[0,BS]])
            self.assertEqual(plan["targets"][0]["file"],old.name)

    def test_refuse_unsupported_signed_and_truncated(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            folder=Path(temp)
            self.make(folder)
            toc=folder/"pakchunk4-Windows_0_P.utoc"
            original=toc.read_bytes()
            for flag in [2,4,16,128]:
                data=bytearray(original);data[80]=flag;toc.write_bytes(data)
                with self.assertRaises(ValueError):
                    m.audit(folder)
            toc.write_bytes(original[:-1])
            with self.assertRaises(ValueError):
                m.audit(folder)

    @unittest.skipUnless(sys.platform=="win32","Windows sparse filesystem integration")
    def test_apply_restore_and_hashes(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp)
            folder=base/"Paks";folder.mkdir()
            old=self.make(folder)
            original={f.name:f.read_bytes() for f in folder.iterdir()}
            plan=m.audit(folder)
            planfile=base/"plan.json";m.save_json(planfile,plan)
            with contextlib.redirect_stdout(io.StringIO()):
                m.apply(planfile,base/"backup",True)
            self.assertEqual(old.stat().st_size,len(original[old.name]))
            self.assertEqual(old.read_bytes()[:BS],bytes(BS))
            self.assertEqual(old.read_bytes()[BS:],original[old.name][BS:])
            self.assertLess(m.Windows().allocated(old),old.stat().st_size)
            for name,data in original.items():
                if name!=old.name:
                    self.assertEqual((folder/name).read_bytes(),data)
            with contextlib.redirect_stdout(io.StringIO()):
                m.restore(base/"backup"/"restore.json")
            for name,data in original.items():
                self.assertEqual((folder/name).read_bytes(),data)
            self.assertEqual(json.loads((base/"backup"/"restore.json").read_text())["state"],"restored")

    @unittest.skipUnless(sys.platform=="win32","Windows file locks")
    def test_open_reader_blocks_apply_before_any_changes(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp);folder=base/"Paks";folder.mkdir()
            old=self.make(folder)
            original=old.read_bytes()
            plan=m.audit(folder)
            planfile=base/"plan.json";m.save_json(planfile,plan)
            with old.open("rb"),contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(OSError):
                    m.apply(planfile,base/"backup",True)
            self.assertEqual(old.read_bytes(),original)

    def test_edited_plan_refused(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp);folder=base/"Paks";folder.mkdir()
            old=self.make(folder)
            original=old.read_bytes()
            plan=m.audit(folder);plan["targets"][0]["ranges"]=[[0,old.stat().st_size]]
            planfile=base/"plan.json";m.save_json(planfile,plan)
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError,"stale or edited"):
                    m.apply(planfile,base/"backup",True)
            self.assertEqual(old.read_bytes(),original)

    @unittest.skipUnless(sys.platform=="win32","Windows recovery integration")
    def test_interrupted_sparse_operation_can_restore(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp);folder=base/"Paks";folder.mkdir()
            old=self.make(folder)
            original={f.name:f.read_bytes() for f in folder.iterdir()}
            planfile=base/"plan.json";m.save_json(planfile,m.audit(folder))
            real=m.Windows.punch
            def fail_after_write(api,f,ranges):
                real(api,f,ranges)
                raise OSError("simulated interruption after sparse ioctl")
            m.Windows.punch=fail_after_write
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(OSError):
                        m.apply(planfile,base/"backup",True)
            finally:
                m.Windows.punch=real
            self.assertNotEqual(old.read_bytes(),original[old.name])
            with contextlib.redirect_stdout(io.StringIO()):
                m.restore(base/"backup"/"restore.json")
            for name,data in original.items():
                self.assertEqual((folder/name).read_bytes(),data)

    def test_alignment_padding_merges_only_known_adjacent_blocks(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            folder=Path(temp)
            # Very small compressed blocks with 16-byte storage alignment.
            stem="pakchunk4-Windows_0_P"
            (folder/(stem+".ucas")).write_bytes(b"A"*32+b"Z"*20)
            h=bytearray(144);h[:16]=m.MAGIC;h[16]=8;h[80]=1
            for offset,value in {20:144,24:3,28:3,32:12,36:1,40:32,44:BS,48:0,52:1}.items():
                struct.pack_into("<I",h,offset,value)
            struct.pack_into("<Q",h,88,2**64-1)
            ids=[cid(1),cid(2),cid(3)]
            body=b"".join(ids)
            body+=b"".join((i*BS).to_bytes(5,"big")+BS.to_bytes(5,"big") for i in range(3))
            body+=b"".join(a.to_bytes(5,"little")+(10).to_bytes(3,"little")+BS.to_bytes(3,"little")+b"\1"
                           for a in [0,16,32])
            body+=b"Oodle"+bytes(27)+bytes(24*3)
            (folder/(stem+".utoc")).write_bytes(h+body)
            fixture(folder,1,[(cid(1),0,BS),(cid(2),BS,BS)],[0,BS],2)
            plan=m.audit(folder)
            # Dead blocks plus their known interblock padding; live block at 32 retained.
            self.assertEqual(plan["targets"][0]["ranges"],[[0,32]])

class TestPrompts(unittest.TestCase):
    def test_clean_path_accepts_quotes_spaces_and_brackets(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            expected=Path(temp)/"a folder [example]"
            self.assertEqual(m.clean_path(' "'+str(expected)+'" '),expected.resolve())

    def test_backup_prompt_retries_existing_directory(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp)
            with mock.patch("builtins.input",side_effect=[str(base),str(base/"new-backup")]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.prompt_path("Backup","backup"),base/"new-backup")

    @unittest.skipUnless(sys.platform=="win32","Windows interactive workflow")
    def test_interactive_audit_only_does_not_apply(self):
        plan={"targets":[{}],"candidate_bytes":1024}
        with mock.patch.object(m,"prompt_path",side_effect=[Path("game"),None]), \
             mock.patch.object(m,"run_audit",return_value=(plan,Path("report.json"),{"targets":[{}],"remaining_candidate_bytes":1024})), \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.interactive()
        apply_mock.assert_not_called()

    @unittest.skipUnless(sys.platform=="win32","Windows interactive workflow")
    def test_interactive_cancel_does_not_apply(self):
        plan={"targets":[{}],"candidate_bytes":1024}
        with mock.patch.object(m,"prompt_path",side_effect=[Path("game"),Path("backup")]), \
             mock.patch.object(m,"run_audit",return_value=(plan,Path("report.json"),{"targets":[{}],"remaining_candidate_bytes":1024})), \
             mock.patch("builtins.input",return_value=""), \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.interactive()
        apply_mock.assert_not_called()

    @unittest.skipUnless(sys.platform=="win32","Windows interactive workflow")
    def test_interactive_passes_chosen_backup_and_confirmation(self):
        plan={"targets":[{}],"candidate_bytes":1024}
        with mock.patch.object(m,"prompt_path",side_effect=[Path("game"),Path("backup")]), \
             mock.patch.object(m,"run_audit",return_value=(plan,Path("report.json"),{"targets":[{}],"remaining_candidate_bytes":1024})), \
             mock.patch("builtins.input",return_value="APPLY"), \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.interactive()
        apply_mock.assert_called_once_with(Path("report.json"),Path("backup"),True)

    @unittest.skipUnless(sys.platform=="win32","Windows interactive workflow")
    def test_no_candidates_does_not_ask_for_backup(self):
        with mock.patch.object(m,"prompt_path",return_value=Path("game")) as prompt_mock, \
             mock.patch.object(m,"run_audit",return_value=({"targets":[]},Path("report.json"),{"targets":[]})), \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.interactive()
        self.assertEqual(prompt_mock.call_count,1)
        apply_mock.assert_not_called()

    def test_default_cli_starts_interactive(self):
        with mock.patch.object(m,"interactive") as interactive_mock:
            m.main([])
        interactive_mock.assert_called_once_with()

    def test_audit_cli_prompts_for_game(self):
        with mock.patch.object(m,"prompt_path",return_value=Path("selected-game")), \
             mock.patch.object(m,"run_audit") as scan:
            m.main(["audit"])
        scan.assert_called_once_with(Path("selected-game"),None)

    def test_explicit_apply_cli_does_not_prompt(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            plan=str(Path(temp)/"plan.json");backup=str(Path(temp)/"backup")
            with mock.patch("builtins.input",side_effect=AssertionError("unexpected prompt")), \
                 mock.patch.object(m,"apply") as apply_mock:
                m.main(["apply",plan,"--backup",backup,"--accept-unverified-patch-order"])
            apply_mock.assert_called_once_with(Path(plan).resolve(),Path(backup).resolve(),True)

    def test_restore_cli_accepts_backup_directory(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            with mock.patch.object(m,"restore") as restore_mock:
                m.main(["restore",temp])
            restore_mock.assert_called_once_with(Path(temp).resolve()/"restore.json")

    def test_reports_have_unique_names_and_stay_outside_game(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp);game=base/"Paks";game.mkdir()
            fixture(game,0,[(cid(1),0,BS)],[0],1)
            fixture(game,1,[(cid(1),0,BS)],[0],1)
            with mock.patch.object(m,"__file__",str(base/"tool"/"bl4_sparse.py")),contextlib.redirect_stdout(io.StringIO()):
                _,first,_=m.run_audit(game)
                _,second,_=m.run_audit(game)
            self.assertNotEqual(first,second)
            self.assertEqual(first.parent,base/"tool"/"reports")
            self.assertTrue(first.is_file() and second.is_file())


class TestRepeatedRuns(unittest.TestCase):
    def test_nonzero_detection_skips_holes_and_allocated_zero_padding(self):
        f=io.BytesIO(b"A"*8+bytes(24)+b"B"*8+bytes(24))
        self.assertEqual(m.nonzero_candidate_ranges(f,[[0,8],[8,32],[32,40],[40,64]],
                                                   [[0,16],[24,48]]),[[0,8],[32,40]])

    def test_nonzero_detection_handles_fragmented_extent_boundaries(self):
        f=io.BytesIO(bytes(12)+b"X"+bytes(19))
        self.assertEqual(m.nonzero_candidate_ranges(f,[[0,8],[8,24],[24,32]],
                                                   [[4,14],[20,28]]),[[8,24]])

    @unittest.skipUnless(sys.platform=="win32","Windows sparse rerun integration")
    def test_repeated_apply_creates_no_backup_and_preserves_original_recovery(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp);game=base/"Paks";game.mkdir()
            old=fixture(game,0,[(cid(1),0,BS)],[0],1)
            fixture(game,1,[(cid(1),0,BS)],[0],1)
            original=old.read_bytes()
            planfile=base/"first-plan.json";m.save_json(planfile,m.audit(game))
            with contextlib.redirect_stdout(io.StringIO()):
                m.apply(planfile,base/"first-backup",True)
            first_backup={p.name:p.read_bytes() for p in (base/"first-backup").iterdir()}
            second=base/"second-plan.json";m.save_json(second,m.audit(game))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                status=m.inspect_candidates(m.audit(game))
                m.apply(second,base/"second-backup",True)
            self.assertEqual(status["remaining_candidate_bytes"],0)
            self.assertEqual(status["already_zero_candidate_bytes"],BS)
            self.assertFalse((base/"second-backup").exists())
            self.assertIn("Nothing further to optimize",output.getvalue())
            self.assertEqual(first_backup,{p.name:p.read_bytes() for p in (base/"first-backup").iterdir()})
            with contextlib.redirect_stdout(io.StringIO()):
                m.restore(base/"first-backup"/"restore.json")
            self.assertEqual(old.read_bytes(),original)

    @unittest.skipUnless(sys.platform=="win32","Windows sparse rerun integration")
    def test_partly_processed_file_keeps_only_intervals_with_nonzero_bytes(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp);game=base/"Paks";game.mkdir()
            old=fixture(game,0,[(cid(1),0,BS),(cid(2),BS,BS),(cid(3),2*BS,BS)],
                        [0,BS,2*BS],3)
            fixture(game,1,[(cid(1),0,BS),(cid(3),BS,BS)],[0,BS],2)
            api=m.Windows()
            with api.open(old,True) as f:
                api.punch(f,[[0,BS]])
            with contextlib.redirect_stdout(io.StringIO()):
                status=m.inspect_candidates(m.audit(game))
            self.assertEqual(status["remaining_candidate_bytes"],BS)
            self.assertEqual(status["targets"][0]["ranges"],[[2*BS,3*BS]])

    @unittest.skipUnless(sys.platform=="win32","Windows guided rerun workflow")
    def test_interactive_already_zero_does_not_prompt_for_backup(self):
        plan={"targets":[{}],"candidate_bytes":1024}
        status={"targets":[],"remaining_candidate_bytes":0,"already_zero_candidate_bytes":1024}
        with mock.patch.object(m,"prompt_path",return_value=Path("game")) as prompt_mock, \
             mock.patch.object(m,"run_audit",return_value=(plan,Path("report.json"),status)), \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.interactive()
        self.assertEqual(prompt_mock.call_count,1)
        apply_mock.assert_not_called()

    @unittest.skipUnless(sys.platform=="win32","Windows allocated extent query")
    def test_allocation_query_handles_multiple_output_pages(self):
        class FakeKernel:
            def DeviceIoControl(self,handle,code,query,query_size,output,output_size,count,unused):
                import ctypes
                import ctypes.wintypes as W
                offset,length=struct.unpack("<qq",query.raw[:16])
                records=struct.pack("<qq",offset,10)
                ctypes.memmove(output,records,len(records))
                ctypes.cast(count,ctypes.POINTER(W.DWORD))[0]=len(records)
                if offset==0:
                    ctypes.set_last_error(234)
                    return False
                return True
        api=m.Windows();api.k=FakeKernel()
        with tempfile.TemporaryFile() as f:
            self.assertEqual(api.allocated_ranges(f,20),[[0,20]])


class TestNoBackup(unittest.TestCase):
    def test_api_requires_separate_data_loss_acknowledgement(self):
        with self.assertRaisesRegex(ValueError,"separate permanent-data-loss"):
            m.apply("not-opened.json",None,True,no_backup=True)
        with self.assertRaisesRegex(ValueError,"Cannot combine"):
            m.apply("not-opened.json","backup",True,no_backup=True,no_backup_confirmed=True)
        with self.assertRaisesRegex(ValueError,"backup folder is required"):
            m.apply("not-opened.json",None,True)

    def test_typed_confirmations_cancel_on_either_mismatch(self):
        for answers in [[""],["APPLY"],["I ACCEPT PERMANENT DATA LOSS",""],["I ACCEPT PERMANENT DATA LOSS","apply"]]:
            with mock.patch("builtins.input",side_effect=answers) as prompt,contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(m.confirm_no_backup())
                self.assertEqual(prompt.call_count,len(answers))

    def test_no_backup_requires_both_exact_phrases(self):
        with mock.patch("builtins.input",side_effect=["I ACCEPT PERMANENT DATA LOSS","DELETE WITHOUT BACKUP"]), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertTrue(m.confirm_no_backup())
        for warning in ["PERMANENT", "NO range backup", "NO automatic rollback", "partial modification",
                        "Kept-byte hashes", "reinstall", "CANNOT restore"]:
            self.assertIn(warning,output.getvalue())

    def test_cli_rejects_combining_backup_and_no_backup(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            m.main(["apply","plan.json","--backup","backup","--no-backup"])
        self.assertEqual(error.exception.code,2)

    def test_cli_accept_flag_cannot_skip_no_backup_confirmation(self):
        with mock.patch("builtins.input",side_effect=[""]) as prompt, \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.main(["apply","plan.json","--no-backup","--accept-unverified-patch-order"])
        prompt.assert_called_once()
        apply_mock.assert_not_called()

    def test_cli_confirmed_no_backup_never_asks_for_backup_folder(self):
        with mock.patch("builtins.input",side_effect=["I ACCEPT PERMANENT DATA LOSS","DELETE WITHOUT BACKUP"]) as prompt, \
             mock.patch.object(m,"prompt_path",side_effect=AssertionError("unexpected backup prompt")), \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.main(["apply","plan.json","--no-backup"])
        self.assertEqual(prompt.call_count,2)
        apply_mock.assert_called_once_with(Path("plan.json").resolve(),None,True,
                                          no_backup=True,no_backup_confirmed=True)

    def test_guided_flag_is_forwarded_explicitly(self):
        with mock.patch.object(m,"interactive") as guided:
            m.main(["--no-backup"])
        guided.assert_called_once_with(no_backup=True)

    @unittest.skipUnless(sys.platform=="win32","Windows no-backup guided workflow")
    def test_guided_cancellation_never_applies(self):
        plan={"targets":[{}]}
        status={"targets":[{}],"remaining_candidate_bytes":BS}
        with mock.patch.object(m,"prompt_path",return_value=Path("game")) as path_prompt, \
             mock.patch.object(m,"run_audit",return_value=(plan,Path("plan.json"),status)), \
             mock.patch("builtins.input",return_value=""), \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.interactive(no_backup=True)
        self.assertEqual(path_prompt.call_count,1)
        apply_mock.assert_not_called()

    @unittest.skipUnless(sys.platform=="win32","Windows no-backup integration")
    def test_no_backup_preserves_retained_bytes_and_cannot_restore(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp);game=base/"Paks";game.mkdir()
            old=fixture(game,0,[(cid(1),0,BS),(cid(2),BS,BS)],[0,BS],2)
            fixture(game,1,[(cid(1),0,BS)],[0],1)
            original={p.name:p.read_bytes() for p in game.iterdir()}
            plan=base/"plan.json";m.save_json(plan,m.audit(game))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                m.apply(plan,None,True,no_backup=True,no_backup_confirmed=True)
            self.assertIn("NO BACKUP WAS CREATED",output.getvalue())
            self.assertEqual(old.read_bytes(),bytes(BS)+original[old.name][BS:])
            for name,data in original.items():
                if name!=old.name:self.assertEqual((game/name).read_bytes(),data)
            self.assertFalse(list(base.rglob("*.ranges.bin")))
            self.assertFalse(list(base.rglob("restore.json")))
            reports=list(base.glob("*.no-backup-*.json"))
            self.assertEqual(len(reports),1)
            journal=json.loads(reports[0].read_text())
            self.assertFalse(journal["recoverable"])
            self.assertEqual(journal["state"],"complete")
            with self.assertRaisesRegex(ValueError,"NO-BACKUP diagnostic"):
                m.restore(reports[0])

    @unittest.skipUnless(sys.platform=="win32","Windows no-backup failure integration")
    def test_no_backup_failure_reports_no_rollback(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp);game=base/"Paks";game.mkdir()
            fixture(game,0,[(cid(1),0,BS)],[0],1)
            fixture(game,1,[(cid(1),0,BS)],[0],1)
            plan=base/"plan.json";m.save_json(plan,m.audit(game))
            real=m.Windows.punch
            def fail_after_write(api,f,ranges):
                real(api,f,ranges)
                raise OSError("simulated interruption")
            with mock.patch.object(m.Windows,"punch",fail_after_write),contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(OSError):
                    m.apply(plan,None,True,no_backup=True,no_backup_confirmed=True)
            self.assertIn("cannot roll it back",errors.getvalue())
            report=next(base.glob("*.no-backup-*.json"))
            self.assertEqual(json.loads(report.read_text())["state"],"writing")
            self.assertFalse(list(base.rglob("*.ranges.bin")))


    @unittest.skipUnless(sys.platform=="win32","Windows no-backup subprocess workflow")
    def test_real_guided_cli_cancel_apply_and_repeat(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            base=Path(temp);game=base/"Game [example]"/"OakGame"/"Content"/"Paks";game.mkdir(parents=True)
            old=fixture(game,0,[(cid(1),0,BS),(cid(2),BS,BS)],[0,BS],2)
            fixture(game,1,[(cid(1),0,BS)],[0],1)
            original=old.read_bytes()
            tool=base/"tool";tool.mkdir();script=tool/"bl4_sparse.py"
            script.write_bytes(SCRIPT.read_bytes())
            def run(answers):
                result=subprocess.run([sys.executable,str(script),"--no-backup"],
                                      input=answers,text=True,capture_output=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                return result.stdout
            output=run(str(game)+"\n\n")
            self.assertIn("Cancelled. No game files changed.",output)
            self.assertEqual(old.read_bytes(),original)
            output=run(str(game)+"\nI ACCEPT PERMANENT DATA LOSS\nDELETE WITHOUT BACKUP\n")
            self.assertIn("NO BACKUP WAS CREATED",output)
            self.assertEqual(old.read_bytes(),bytes(BS)+original[BS:])
            self.assertFalse(list(base.rglob("*.ranges.bin")))
            self.assertFalse(list(base.rglob("restore.json")))
            self.assertEqual(len(list(tool.rglob("*.no-backup-*.json"))),1)
            output=run(str(game)+"\n")
            self.assertIn("Already-zero candidate data needs no new backup",output)
            self.assertNotIn("Type I ACCEPT",output)
            self.assertEqual(len(list(tool.rglob("*.no-backup-*.json"))),1)


if __name__=="__main__":
    unittest.main(verbosity=2)
