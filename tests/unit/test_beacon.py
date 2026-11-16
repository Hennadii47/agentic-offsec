import json

from lib.beacon import read_hits
from lib.opsec import Signer


def test_a_hit_verifies_only_with_the_signing_key(tmp_path):
    signer = Signer.from_key("k")
    path = tmp_path / "hits.jsonl"
    path.write_text("\n".join([
        json.dumps({"name": "a", "version": "1", "at": "t", "sig": signer.sign("a", "1")}),
        json.dumps({"name": "b", "version": "1", "at": "t", "sig": "deadbeef"}),
        json.dumps({"name": "c", "version": "1", "at": "t"}),
    ]))
    hits = read_hits(path, signer)
    assert [hit.verified for hit in hits] == [True, False, False]


def test_a_broken_line_is_skipped_not_fatal(tmp_path):
    path = tmp_path / "hits.jsonl"
    path.write_text('not json\n{"name": "a", "version": "1", "sig": "x"}\n')
    assert len(read_hits(path, Signer.from_key("k"))) == 1


def test_read_source_takes_a_file_and_a_namespace(tmp_path, monkeypatch):
    from lib import beacon
    from lib.opsec import Signer
    signer = Signer.from_key("k")
    path = tmp_path / "hits.jsonl"
    path.write_text(json.dumps({"name": "a", "version": "1", "at": "t", "sig": signer.sign("a", "1")}) + "\n")
    assert beacon.read_source(str(path), signer)[0].verified is True
    monkeypatch.setattr(beacon, "from_cloudflare", lambda ns: [{"name": "a", "version": "1", "at": "t",
                                                               "sig": signer.sign("a", "1")}])
    assert beacon.read_source("cf://namespace", signer)[0].verified is True
