defmodule Chronicle.CanonicalTest do
  use ExUnit.Case, async: true

  alias Chronicle.Canonical

  @vectors [
    {nil, "0100"},
    {false, "0101"},
    {true, "0102"},
    {0, "0103000000000100"},
    {-1, "0103010000000101"},
    {"audit", "0104000000056175646974"},
    {:event, "0106000000056576656e74"},
    {[1, "x"], "0107000000020000000d03000000000101040000000178"},
    {%{b: 2, a: 1}, "0109000000020000001a0600000001610300000000010106000000016203000000000102"},
    {{:ok, %{id: "42"}},
     "0108000000020000001e06000000026f6b09000000010000000e0600000002696404000000023432"}
  ]

  test "version 1 golden vectors remain byte-for-byte stable" do
    Enum.each(@vectors, fn {term, expected} ->
      assert term |> Canonical.encode() |> Base.encode16(case: :lower) == expected
    end)
  end

  test "map insertion order cannot change the encoding" do
    pairs =
      for index <- 1..100 do
        {"field-#{index}", %{value: rem(index * 37, 101), flags: [odd?: rem(index, 2) == 1]}}
      end

    expected = pairs |> Map.new() |> Canonical.encode()
    :rand.seed(:exsss, {17, 29, 43})

    for _iteration <- 1..100 do
      assert pairs |> Enum.shuffle() |> Map.new() |> Canonical.encode() == expected
    end
  end

  test "rejects over-deep and runtime-bearing terms" do
    over_deep = Enum.reduce(1..65, :leaf, fn _index, nested -> [nested] end)

    assert_raise ArgumentError, ~r/nesting depth/, fn -> Canonical.encode(over_deep) end
    assert_raise ArgumentError, ~r/proper lists/, fn -> Canonical.encode([1 | 2]) end
    assert_raise ArgumentError, ~r/a pid/, fn -> Canonical.encode(self()) end
    assert_raise ArgumentError, ~r/structs/, fn -> Canonical.encode(Date.utc_today()) end
  end
end
