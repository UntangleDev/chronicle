defmodule Chronicle.ValueTest do
  @moduledoc """
  Normalization decides what actually reaches the ledger, so its edges matter:
  a term it cannot encode must not reach `Chronicle.Canonical`, and a protected
  value must not survive as itself.
  """

  use ExUnit.Case, async: true

  alias Chronicle.Value

  defmodule Point do
    @moduledoc false
    defstruct [:x, :y]
  end

  describe "scalars" do
    test "passes through what the canonical format accepts" do
      assert Value.normalize(nil) == nil
      assert Value.normalize(true) == true
      assert Value.normalize("text") == "text"
      assert Value.normalize(42) == 42
      assert Value.normalize(1.5) == 1.5
    end

    test "converts atoms to strings so the ledger holds no runtime terms" do
      assert Value.normalize(:pending) == "pending"
      assert Value.normalize(%{status: :ok}) == %{"status" => "ok"}
    end

    test "converts date and time structs to ISO 8601" do
      assert Value.normalize(~U[2026-07-25 12:00:00Z]) == "2026-07-25T12:00:00Z"
      assert Value.normalize(~N[2026-07-25 12:00:00]) == "2026-07-25T12:00:00"
      assert Value.normalize(~D[2026-07-25]) == "2026-07-25"
      assert Value.normalize(~T[12:00:00]) == "12:00:00"
    end

    test "inspects terms that cannot be represented" do
      assert Value.normalize(self()) =~ "#PID"
      assert Value.normalize(make_ref()) =~ "#Reference"
      assert Value.normalize(&Function.identity/1) =~ "Function"
    end
  end

  describe "structures" do
    test "flattens a plain struct to its fields" do
      assert Value.normalize(%Point{x: 1, y: 2}) == %{"x" => 1, "y" => 2}
    end

    test "converts tuples to lists, since the canonical format keeps them distinct" do
      assert Value.normalize({:ok, 1}) == ["ok", 1]
    end

    test "normalizes recursively through maps and lists" do
      assert Value.normalize(%{a: [%{b: :c}]}) == %{"a" => [%{"b" => "c"}]}
    end

    test "stringifies non-atom, non-binary keys" do
      assert Value.normalize(%{1 => "one"}) == %{"1" => "one"}
    end
  end

  describe "protection" do
    test "redacts, hashes, and omits by marker" do
      assert Value.normalize(Chronicle.secret("x")) == "[REDACTED]"
      assert "sha256:" <> _ = Value.normalize(Chronicle.hash("x"))
      assert Value.normalize(%{drop: Chronicle.omit(), keep: 1}) == %{"keep" => 1}
    end

    test "removes omitted items from lists as well as maps" do
      assert Value.normalize([1, Chronicle.omit(), 2]) == [1, 2]
    end

    test "hashing is deterministic and value-dependent" do
      assert Value.normalize(Chronicle.hash("a")) == Value.normalize(Chronicle.hash("a"))
      refute Value.normalize(Chronicle.hash("a")) == Value.normalize(Chronicle.hash("b"))
    end

    test "a value that merely looks like the omit sentinel is kept" do
      assert Value.normalize(%{a: :__audit_omit__}) == %{"a" => "__audit_omit__"}
    end

    test "canonical/1 applies no protection, so integrity input is the real value" do
      assert Value.canonical(%{password: "hunter2"}) == %{"password" => "hunter2"}
      assert Value.normalize(%{password: "hunter2"}) == %{"password" => "[REDACTED]"}
    end
  end

  describe "already-normalized subtrees" do
    test "a Raw value passes through untouched" do
      raw = %Chronicle.Value.Raw{value: %{"password" => nil, "complete" => true}}

      assert Value.normalize(%{snapshot: raw}) == %{
               "snapshot" => %{"password" => nil, "complete" => true}
             }
    end
  end

  test "everything normalization produces is canonically encodable" do
    payload = %{
      atom: :ok,
      tuple: {:a, 1},
      list: [1, "two", :three],
      nested: %{when: ~U[2026-07-25 12:00:00Z]},
      pid: self()
    }

    assert is_binary(payload |> Value.normalize() |> Chronicle.Canonical.encode())
  end
end
