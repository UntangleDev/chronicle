defmodule Chronicle.ReferenceTest do
  @moduledoc """
  A reference is exactly a type and an id, and is the only thing stored — the
  struct and the row cannot disagree. These cover how arbitrary values reach
  that shape.
  """

  use ExUnit.Case, async: true

  alias Chronicle.{Classifier, Reference}

  defmodule User do
    @moduledoc false
    defstruct [:id, :email]
  end

  defmodule Widget do
    @moduledoc false
    defstruct [:id, :type]
  end

  defimpl Chronicle.Identity, for: Chronicle.ReferenceTest.Widget do
    def audit_identity(widget), do: Chronicle.ref("widget", widget.id)
  end

  describe "resolve/1" do
    test "a struct with an id falls back to its module name" do
      assert Reference.resolve(%User{id: 7}) == %{"type" => inspect(User), "id" => "7"}
    end

    test "a custom implementation wins over the fallback" do
      assert Reference.resolve(%Widget{id: "w-1"}) == %{"type" => "widget", "id" => "w-1"}
    end

    test "a plain map with an id is taken as-is" do
      assert Reference.resolve(%{id: 1, type: "thing"}) == %{"type" => "thing", "id" => "1"}
    end

    test "a map with only an id gets the default type" do
      assert Reference.resolve(%{id: 1}) == %{"type" => "entity", "id" => "1"}
    end

    test "string keys work as well as atoms" do
      assert Reference.resolve(%{"id" => 1, "type" => "thing"}) ==
               %{"type" => "thing", "id" => "1"}
    end

    test "nil resolves to nil" do
      assert Reference.resolve(nil) == nil
    end

    test "a value with no derivable identity is reported, not guessed at" do
      assert_raise ArgumentError, ~r/cannot derive an audit identity/, fn ->
        Reference.resolve("just a string")
      end
    end

    test "extra keys are dropped at the boundary, not silently at storage" do
      assert Reference.resolve(%{"type" => "user", "id" => 1, "email" => "a@b.c"}) ==
               %{"type" => "user", "id" => "1"}
    end

    test "is idempotent" do
      once = Reference.resolve(Chronicle.ref("account", "a-1"))
      assert Reference.resolve(once) == once
    end
  end

  describe "digest" do
    test "identifies a composite key with one indexable value" do
      composite = %{"type" => "membership", "id" => %{"account" => "a", "user" => "u"}}
      assert "sha256:" <> _ = Reference.id(composite)
    end

    test "is independent of key order" do
      a = %{"type" => "m", "id" => %{"x" => 1, "y" => 2}}
      b = %{"type" => "m", "id" => %{"y" => 2, "x" => 1}}
      assert Reference.id(a) == Reference.id(b)
    end

    test "distinguishes different keys and different types" do
      base = %{"type" => "m", "id" => %{"x" => 1}}
      refute Reference.id(base) == Reference.id(%{base | "id" => %{"x" => 2}})
      refute Reference.id(base) == Reference.id(%{base | "type" => "n"})
    end
  end

  describe "Chronicle.ref and actor" do
    test "build a reference from an explicit type and id" do
      assert Chronicle.ref("account", "a-1") == %{"type" => "account", "id" => "a-1"}
      assert Chronicle.actor(:user, 7) == %{"type" => "user", "id" => 7}
    end
  end

  describe "Classifier" do
    test ":default fails only on an error result" do
      assert Classifier.classify(:error, :default) == :failure
      assert Classifier.classify({:error, :nope}, :default) == :failure
      assert Classifier.classify(:ok, :default) == :success
      assert Classifier.classify(%{id: 1}, :default) == :success
    end

    test ":result_tuple is unknown for anything that is not a result" do
      assert Classifier.classify(:ok, :result_tuple) == :success
      assert Classifier.classify({:ok, 1}, :result_tuple) == :success
      assert Classifier.classify(:error, :result_tuple) == :failure
      assert Classifier.classify({:error, :x}, :result_tuple) == :failure
      assert Classifier.classify(:something, :result_tuple) == :unknown
    end

    test ":boolean, :http_status, and :always_success" do
      assert Classifier.classify(true, :boolean) == :success
      assert Classifier.classify(false, :boolean) == :failure
      assert Classifier.classify(:other, :boolean) == :unknown

      assert Classifier.classify(200, :http_status) == :success
      assert Classifier.classify(404, :http_status) == :failure
      assert Classifier.classify(%{status: 500}, :http_status) == :failure
      assert Classifier.classify(:no_status, :http_status) == :unknown

      assert Classifier.classify({:error, :x}, :always_success) == :success
      assert Classifier.classify({:error, :x}, nil) == :success
    end

    test "a one-argument function classifies" do
      assert Classifier.classify(7, fn n -> if n > 5, do: :success, else: :failure end) ==
               :success
    end

    test "an unknown classifier names the valid ones" do
      assert_raise ArgumentError, ~r/:classify must be one of/, fn ->
        Classifier.classify(:x, :nonsense)
      end
    end
  end
end
