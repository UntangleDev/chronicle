defmodule Chronicle.IntegrityTest do
  use ExUnit.Case, async: true

  alias Chronicle.Integrity

  setup do
    key = :crypto.strong_rand_bytes(32)
    %{key: key, opts: [ledger: "primary", key_id: "key-1", key: key]}
  end

  test "verifies content, sequence, previous digest, and HMAC", %{key: key, opts: opts} do
    assert {:ok, first} =
             Integrity.build(:event, Chronicle.ID.generate(), %{amount: 10}, 1, nil, opts)

    assert {:ok, second} =
             Integrity.build(
               :group,
               Chronicle.ID.generate(),
               %{events: [%{type: "payment.captured"}]},
               2,
               first.digest,
               opts
             )

    assert :ok = Integrity.verify(first, %{amount: 10}, nil, 1, key)

    assert :ok =
             Integrity.verify(
               second,
               %{events: [%{type: "payment.captured"}]},
               first.digest,
               2,
               key
             )
  end

  test "integrity suite has a stable published vector" do
    key = :binary.list_to_bin(Enum.to_list(0..31))

    assert {:ok, entry} =
             Integrity.build(
               :event,
               "00000000-0000-0000-0000-000000000001",
               %{amount: 10, currency: "GBP"},
               1,
               nil,
               ledger: "primary",
               key_id: "key-1",
               key: key
             )

    assert entry.algorithm == "audit-binary-v1-hmac-sha256-v2"
    assert entry.canonical_version == 1

    assert entry.content_digest ==
             "b2b71131f8115915c3695b30a45dfe39bbe9e510931105ba0aab786d54d8998b"

    assert entry.digest ==
             "9f38890172f02b3882576705969e4705a96f4d3fb80fb80db560cd02c1a7f7d5"

    assert entry.signature ==
             "65bc1071e6fb83ece5b787abf4d08d1099a4d2046ecee49d06710db0fb5f665e"
  end

  test "detects modified content", %{key: key, opts: opts} do
    {:ok, entry} = Integrity.build(:event, Chronicle.ID.generate(), %{amount: 10}, 1, nil, opts)

    assert {:error, {:content_digest_mismatch, 1}} =
             Integrity.verify(entry, %{amount: 11}, nil, 1, key)
  end

  test "detects deletion and reordering through sequence and link checks", %{
    key: key,
    opts: opts
  } do
    {:ok, first} = Integrity.build(:event, Chronicle.ID.generate(), %{n: 1}, 1, nil, opts)

    {:ok, second} =
      Integrity.build(:event, Chronicle.ID.generate(), %{n: 2}, 2, first.digest, opts)

    assert {:error, {:unexpected_sequence, 2}} =
             Integrity.verify(second, %{n: 2}, nil, 1, key)

    assert {:error, {:previous_digest_mismatch, 2}} =
             Integrity.verify(second, %{n: 2}, "wrong", 2, key)
  end

  test "detects a forged signature", %{key: key, opts: opts} do
    {:ok, entry} = Integrity.build(:event, Chronicle.ID.generate(), %{}, 1, nil, opts)
    forged = %{entry | signature: String.duplicate("0", 64)}

    assert {:error, {:signature_mismatch, 1}} =
             Integrity.verify(forged, %{}, nil, 1, key)
  end

  test "rejects short keys and resolves rotated verification keys", %{key: key, opts: opts} do
    assert {:error, {:integrity_key_too_short, 5, 32}} =
             Integrity.build(:event, Chronicle.ID.generate(), %{}, 1, nil,
               key_id: "short",
               key: "short"
             )

    assert {:ok, ^key} = Integrity.verification_key("key-1", keys: %{"key-1" => key})

    assert {:ok, ^key} =
             Integrity.verification_key("key-1",
               key_id: "key-1",
               key: key,
               keys: %{"old-key" => :crypto.strong_rand_bytes(32)}
             )

    assert {:error, {:verification_key_not_found, "missing"}} =
             Integrity.verification_key("missing", opts)
  end

  test "key epochs select signing keys and reject historical keys outside their range" do
    first_key = :crypto.strong_rand_bytes(32)
    second_key = :crypto.strong_rand_bytes(32)

    opts = [
      ledger: "primary",
      keys: %{"key-1" => first_key, "key-2" => second_key},
      key_epochs: %{
        "key-1" => [from: 1, through: 2],
        "key-2" => [from: 3]
      }
    ]

    assert {:ok, first} = Integrity.build(:event, Chronicle.ID.generate(), %{n: 1}, 2, nil, opts)
    assert first.key_id == "key-1"

    assert {:ok, second} =
             Integrity.build(:event, Chronicle.ID.generate(), %{n: 2}, 3, first.digest, opts)

    assert second.key_id == "key-2"
    assert {:ok, ^first_key} = Integrity.verification_key("key-1", 2, opts)

    assert {:error, {:key_not_valid_at_sequence, "key-1", 3, {1, 2}}} =
             Integrity.verification_key("key-1", 3, opts)
  end

  test "epoch policy fails closed on gaps, overlap, and keys without epochs" do
    key = :crypto.strong_rand_bytes(32)

    assert {:error, {:no_signing_key_for_sequence, 2}} =
             Integrity.build(:event, Chronicle.ID.generate(), %{}, 2, nil,
               ledger: "primary",
               keys: %{"key-1" => key},
               key_epochs: %{"key-1" => [from: 3]}
             )

    assert {:error, {:overlapping_key_epochs, 3, ids}} =
             Integrity.build(:event, Chronicle.ID.generate(), %{}, 3, nil,
               ledger: "primary",
               keys: %{"key-1" => key, "key-2" => key},
               key_epochs: %{"key-1" => [from: 1], "key-2" => [from: 3]}
             )

    assert Enum.sort(ids) == ["key-1", "key-2"]

    assert {:error, {:key_epoch_not_found, "key-2"}} =
             Integrity.verification_key("key-2", 3,
               ledger: "primary",
               keys: %{"key-2" => key},
               key_epochs: %{"key-1" => [from: 1]}
             )
  end
end
