from src.core.bootstrap import bootstrap_runtime_files


def test_bootstrap_runtime_files_seeds_mutable_assets(tmp_path):
    config_dir = tmp_path / "config"
    keys_dir = tmp_path / "resources" / "keys"
    config_dir.mkdir(parents=True)
    keys_dir.mkdir(parents=True)

    (config_dir / "config.example.yaml").write_text("threads: 7\nrate_limit: 13\n")
    (config_dir / "api_keys.example.json").write_text('{"keys": [], "updated_at": "2026-05-01T00:00:00Z"}\n')

    result = bootstrap_runtime_files(base_dir=tmp_path)

    assert result["config"] is True
    assert result["api_keys"] is True
    assert result["evidence_key"] is True

    assert (config_dir / "config.yaml").exists()
    assert (config_dir / "api_keys.json").exists()
    evidence_key = keys_dir / "evidence_key.priv"
    assert evidence_key.exists()
    assert len(evidence_key.read_bytes()) == 32


def test_bootstrap_runtime_files_is_idempotent(tmp_path):
    config_dir = tmp_path / "config"
    keys_dir = tmp_path / "resources" / "keys"
    config_dir.mkdir(parents=True)
    keys_dir.mkdir(parents=True)

    (config_dir / "config.yaml").write_text("threads: 21\n")
    (config_dir / "api_keys.json").write_text('{"keys": [], "updated_at": "2026-05-01T00:00:00Z"}\n')
    (keys_dir / "evidence_key.priv").write_bytes(b"0" * 32)

    result = bootstrap_runtime_files(base_dir=tmp_path)

    assert result["config"] is False
    assert result["api_keys"] is False
    assert result["evidence_key"] is False
    assert (config_dir / "config.yaml").read_text() == "threads: 21\n"
    assert (keys_dir / "evidence_key.priv").read_bytes() == b"0" * 32
