from pathlib import Path

from lib.cloud import extract_keys, rank, scan
from lib.schemas import CloudKey


def test_env_file_yields_cloud_ssh_and_db(root):
    kinds = {key.kind for key in scan(root / "fixtures/cloud/.env")}
    assert {"yandex", "ssh", "db"} <= kinds


def test_kubeconfig_is_recognised(root):
    kinds = {key.kind for key in scan(root / "fixtures/cloud/kubeconfig")}
    assert "k8s" in kinds


def test_tfstate_holds_aws_and_gcp(root):
    kinds = {key.kind for key in scan(root / "fixtures/cloud/terraform.tfstate")}
    assert {"aws", "gcp"} == kinds


def test_no_key_value_is_ever_returned(root):
    keys = scan(root / "fixtures/cloud/terraform.tfstate")
    blob = " ".join(key.fingerprint for key in keys)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


def test_rank_puts_cloud_admin_first():
    keys = [CloudKey(kind="generic", source="a", fingerprint="x"),
            CloudKey(kind="aws", source="b", fingerprint="y"),
            CloudKey(kind="k8s", source="c", fingerprint="z")]
    assert [key.kind for key in rank(keys)] == ["aws", "k8s", "generic"]

def test_extract_is_deduplicated():
    text = "AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE"
    assert len(extract_keys(text, "s")) == 1
