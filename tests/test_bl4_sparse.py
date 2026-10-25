import contextlib
import importlib.util
import io
import json
from pathlib import Path
import random
import struct
import sys
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
             mock.patch.object(m,"run_audit",return_value=(plan,Path("report.json"))), \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.interactive()
        apply_mock.assert_not_called()

    @unittest.skipUnless(sys.platform=="win32","Windows interactive workflow")
    def test_interactive_cancel_does_not_apply(self):
        plan={"targets":[{}],"candidate_bytes":1024}
        with mock.patch.object(m,"prompt_path",side_effect=[Path("game"),Path("backup")]), \
             mock.patch.object(m,"run_audit",return_value=(plan,Path("report.json"))), \
             mock.patch("builtins.input",return_value=""), \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.interactive()
        apply_mock.assert_not_called()

    @unittest.skipUnless(sys.platform=="win32","Windows interactive workflow")
    def test_interactive_passes_chosen_backup_and_confirmation(self):
        plan={"targets":[{}],"candidate_bytes":1024}
        with mock.patch.object(m,"prompt_path",side_effect=[Path("game"),Path("backup")]), \
             mock.patch.object(m,"run_audit",return_value=(plan,Path("report.json"))), \
             mock.patch("builtins.input",return_value="APPLY"), \
             mock.patch.object(m,"apply") as apply_mock,contextlib.redirect_stdout(io.StringIO()):
            m.interactive()
        apply_mock.assert_called_once_with(Path("report.json"),Path("backup"),True)

    @unittest.skipUnless(sys.platform=="win32","Windows interactive workflow")
    def test_no_candidates_does_not_ask_for_backup(self):
        with mock.patch.object(m,"prompt_path",return_value=Path("game")) as prompt_mock, \
             mock.patch.object(m,"run_audit",return_value=({"targets":[]},Path("report.json"))), \
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
                _,first=m.run_audit(game)
                _,second=m.run_audit(game)
            self.assertNotEqual(first,second)
            self.assertEqual(first.parent,base/"tool"/"reports")
            self.assertTrue(first.is_file() and second.is_file())


if __name__=="__main__":
    unittest.main(verbosity=2)
