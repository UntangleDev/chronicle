defmodule Chronicle.CanonicalLimitsTest do
  @moduledoc """
  The canonical format is the permanent input to every signature, so its
  contract has to hold exactly: same value, same bytes; different value,
  different bytes; and anything it cannot represent is refused rather than
  encoded approximately.
  """

  use ExUnit.Case, async: true

  alias Chronicle.Canonical

  describe "determinism" do
    test "map key order does not change the encoding" do
      assert Canonical.encode(%{"a" => 1, "b" => 2}) == Canonical.encode(%{"b" => 2, "a" => 1})
    end

    test "values that differ encode differently" do
      pairs = [
        {1, 1.0},
        {1, "1"},
        {nil, false},
        {"a", :a},
        {[1, 2], {1, 2}},
        {%{"a" => 1}, [{"a", 1}]},
        {-1, 1}
      ]

      for {left, right} <- pairs do
        refute Canonical.encode(left) == Canonical.encode(right),
               "#{inspect(left)} and #{inspect(right)} must not collide"
      end
    end

    test "nested structures encode stably" do
      value = %{"list" => [1, %{"deep" => [true, nil]}], "n" => -42}
      assert Canonical.encode(value) == Canonical.encode(value)
    end

    test "the leading byte is the format version" do
      assert <<version, _rest::binary>> = Canonical.encode("x")
      assert version == Canonical.version()
    end
  end

  describe "refuses what it cannot represent" do
    test "structs, which must be normalized first" do
      assert_raise ArgumentError, ~r/does not support structs/, fn ->
        Canonical.encode(%{at: ~U[2026-07-25 12:00:00Z]})
      end
    end

    test "runtime-bearing terms" do
      for value <- [self(), make_ref(), &Function.identity/1] do
        assert_raise ArgumentError, ~r/does not support/, fn -> Canonical.encode(value) end
      end
    end

    test "the BEAM cannot construct a non-finite float, so none can reach the ledger" do
      assert_raise MatchError, fn -> <<_::float-64>> = <<0x7F, 0xF0, 0, 0, 0, 0, 0, 0>> end
      assert_raise ArithmeticError, fn -> 1.0e308 * 10 end

      assert_raise ArgumentError, fn ->
        :erlang.binary_to_term(<<131, 70, 127, 240, 0, 0, 0, 0, 0, 0>>)
      end
    end

    test "improper lists" do
      assert_raise ArgumentError, ~r/proper lists/, fn -> Canonical.encode([1 | 2]) end
    end

    test "a non-binary bitstring" do
      assert_raise ArgumentError, ~r/bitstring/, fn -> Canonical.encode(<<1::size(3)>>) end
    end
  end

  describe "resource limits are part of the format" do
    test "nesting depth is bounded" do
      deep = Enum.reduce(1..70, "leaf", fn _, acc -> [acc] end)
      assert_raise ArgumentError, ~r/nesting depth/, fn -> Canonical.encode(deep) end
    end

    test "collection length is bounded" do
      assert_raise ArgumentError, ~r/exceeds maximum length/, fn ->
        Canonical.encode(Enum.to_list(1..100_001))
      end
    end

    test "integer magnitude is bounded" do
      assert_raise ArgumentError, ~r/integer magnitude/, fn ->
        Canonical.encode(Integer.pow(2, 8 * 4096 + 1))
      end
    end

    test "a value at the depth limit still encodes" do
      ok = Enum.reduce(1..60, "leaf", fn _, acc -> [acc] end)
      assert is_binary(Canonical.encode(ok))
    end

    test "lists stop at the aggregate budget before visiting a later unsupported term" do
      chunk = String.duplicate("x", 1_024 * 1_024)
      over_budget = List.duplicate(chunk, 33) ++ [self()]

      error =
        assert_raise ArgumentError, ~r/encoded term size/, fn ->
          Canonical.encode(over_budget)
        end

      refute Exception.message(error) =~ "pid"
    end

    test "tuples stop at the aggregate budget before visiting a later unsupported term" do
      chunk = String.duplicate("x", 1_024 * 1_024)
      over_budget = List.to_tuple(List.duplicate(chunk, 33) ++ [self()])

      error =
        assert_raise ArgumentError, ~r/encoded term size/, fn ->
          Canonical.encode(over_budget)
        end

      refute Exception.message(error) =~ "pid"
    end

    test "maps encode values in canonical key order and stop before a later unsupported value" do
      chunk = String.duplicate("x", 1_024 * 1_024)

      over_budget =
        1..33
        |> Map.new(fn index -> {String.pad_leading(Integer.to_string(index), 2, "0"), chunk} end)
        |> Map.put("zz", self())

      error =
        assert_raise ArgumentError, ~r/encoded term size/, fn ->
          Canonical.encode(over_budget)
        end

      refute Exception.message(error) =~ "pid"
    end
  end

  describe "integrity uses it end to end" do
    test "an entry verifies against its own payload" do
      key = :crypto.strong_rand_bytes(32)
      opts = [ledger: "primary", key_id: "k", key: key]
      payload = %{"a" => 1, "nested" => [1, 2, 3]}

      assert {:ok, entry} = Chronicle.Integrity.build(:event, "id-1", payload, 1, nil, opts)
      assert :ok = Chronicle.Integrity.verify_entry(entry, payload, nil, 1, opts)
    end

    test "a payload whose keys were reordered still verifies" do
      key = :crypto.strong_rand_bytes(32)
      opts = [ledger: "primary", key_id: "k", key: key]

      assert {:ok, entry} =
               Chronicle.Integrity.build(:event, "id-1", %{"a" => 1, "b" => 2}, 1, nil, opts)

      assert :ok =
               Chronicle.Integrity.verify_entry(entry, %{"b" => 2, "a" => 1}, nil, 1, opts)
    end

    test "a different key does not verify" do
      key = :crypto.strong_rand_bytes(32)
      other = :crypto.strong_rand_bytes(32)
      opts = [ledger: "primary", key_id: "k", key: key]

      assert {:ok, entry} = Chronicle.Integrity.build(:event, "id-1", %{}, 1, nil, opts)

      assert {:error, {:signature_mismatch, 1}} =
               Chronicle.Integrity.verify_entry(
                 entry,
                 %{},
                 nil,
                 1,
                 ledger: "primary",
                 key_id: "k",
                 key: other
               )
    end

    test "an entry built for one position does not verify at another" do
      key = :crypto.strong_rand_bytes(32)
      opts = [ledger: "primary", key_id: "k", key: key]

      assert {:ok, entry} = Chronicle.Integrity.build(:event, "id-1", %{}, 2, "abc", opts)

      assert {:error, {:unexpected_sequence, 2}} =
               Chronicle.Integrity.verify_entry(entry, %{}, "abc", 3, opts)

      assert {:error, {:previous_digest_mismatch, 2}} =
               Chronicle.Integrity.verify_entry(entry, %{}, "other", 2, opts)
    end
  end

  describe "key sources" do
    test "resolves each supported form" do
      key = :crypto.strong_rand_bytes(32)

      assert {:ok, ^key} = Chronicle.Integrity.resolve_key(key)
      assert {:ok, ^key} = Chronicle.Integrity.resolve_key(fn -> key end)
      assert {:ok, ^key} = Chronicle.Integrity.resolve_key({:base64, Base.encode64(key)})

      # An environment variable holds text, so the raw form needs a printable key.
      printable = String.duplicate("k", 32)
      System.put_env("CHRONICLE_TEST_KEY", printable)
      assert {:ok, ^printable} = Chronicle.Integrity.resolve_key({:system, "CHRONICLE_TEST_KEY"})

      System.put_env("CHRONICLE_TEST_KEY_B64", Base.encode64(key))

      assert {:ok, ^key} =
               Chronicle.Integrity.resolve_key({:system, "CHRONICLE_TEST_KEY_B64", :base64})
    after
      System.delete_env("CHRONICLE_TEST_KEY")
      System.delete_env("CHRONICLE_TEST_KEY_B64")
    end

    test "reports each way a key can be unusable" do
      assert {:error, :integrity_key_not_configured} = Chronicle.Integrity.resolve_key(nil)

      assert {:error, {:integrity_key_too_short, 3, 32}} =
               Chronicle.Integrity.resolve_key("abc")

      assert {:error, {:invalid_base64_integrity_key, :inline}} =
               Chronicle.Integrity.resolve_key({:base64, "not base64!"})

      assert {:error, {:environment_variable_not_set, "CHRONICLE_MISSING"}} =
               Chronicle.Integrity.resolve_key({:system, "CHRONICLE_MISSING"})

      assert {:error, {:invalid_integrity_key_source, :nope}} =
               Chronicle.Integrity.resolve_key(:nope)
    end

    test "a resolver that raises is reported rather than crashing the write" do
      assert {:error, {:integrity_key_resolution_failed, RuntimeError}} =
               Chronicle.Integrity.resolve_key(fn -> raise "vault down" end)
    end

    test "a resolver may return a result tuple" do
      key = :crypto.strong_rand_bytes(32)
      assert {:ok, ^key} = Chronicle.Integrity.resolve_key(fn -> {:ok, key} end)
      assert {:error, :nope} = Chronicle.Integrity.resolve_key(fn -> {:error, :nope} end)
    end
  end
end
