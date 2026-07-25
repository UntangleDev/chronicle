defmodule Chronicle.HistoryEdgesTest do
  @moduledoc """
  Reconstruction must fail closed. Every branch here is a case where returning
  a plausible-looking record would be worse than returning an error.
  """

  use ExUnit.Case, async: false

  use Chronicle

  alias Chronicle.Test.Databases

  defmodule Post do
    use Ecto.Schema

    @primary_key {:id, :binary_id, autogenerate: true}
    schema "posts" do
      field :title, :string
      field :views, :integer
    end
  end

  setup do
    {repo, prefix} = Databases.start!(:sqlite)
    Databases.configure!(repo, prefix)

    Databases.create_table!(
      repo,
      prefix,
      "posts",
      "id TEXT PRIMARY KEY, title TEXT, views INTEGER"
    )

    {:ok, post} = Chronicle.insert(Ecto.Changeset.change(%Post{}, %{title: "v1", views: 1}))
    {:ok, post} = Chronicle.update(Ecto.Changeset.change(post, %{title: "v2"}))

    %{repo: repo, post: post}
  end

  describe "selectors" do
    test "reads by version, by event, by time, and latest", %{post: post} do
      assert {:ok, [latest, first]} = Chronicle.history(post)

      assert {:ok, %Post{title: "v1"}} = Chronicle.at(post, version: 1)
      assert {:ok, %Post{title: "v2"}} = Chronicle.at(post, version: 2)
      assert {:ok, %Post{title: "v2"}} = Chronicle.at(post, [])

      assert {:ok, %Post{title: "v1"}} = Chronicle.at(post, event: first.event.id)
      assert {:ok, %Post{title: "v2"}} = Chronicle.at(post, event: latest.event.id)

      assert {:ok, %Post{title: "v2"}} = Chronicle.at(post, at: DateTime.utc_now())
    end

    test "rejects two selectors at once rather than picking one", %{post: post} do
      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.at(post, version: 1, at: DateTime.utc_now())
    end

    test "rejects a malformed selector", %{post: post} do
      assert {:error, %Chronicle.Error{reason: :invalid_query}} = Chronicle.at(post, version: 0)
      assert {:error, %Chronicle.Error{reason: :invalid_query}} = Chronicle.at(post, event: "")
      assert {:error, %Chronicle.Error{reason: :invalid_query}} = Chronicle.at(post, at: "today")
    end

    test "reports a version that does not exist", %{post: post} do
      assert {:error, %Chronicle.Error{reason: :version_not_found}} =
               Chronicle.at(post, version: 99)

      assert {:error, %Chronicle.Error{reason: :version_not_found}} =
               Chronicle.at(post, event: Ecto.UUID.generate())

      assert {:error, %Chronicle.Error{reason: :version_not_found}} =
               Chronicle.at(post, at: ~U[2000-01-01 00:00:00Z])
    end

    test "reports a record with no history at all" do
      assert {:error, %Chronicle.Error{reason: :record_history_not_found}} =
               Chronicle.at(Post, Ecto.UUID.generate(), [])
    end
  end

  describe "paging" do
    test "limit and offset select a window", %{post: post} do
      assert {:ok, [%{version: 2}]} = Chronicle.history(post, limit: 1)
      assert {:ok, [%{version: 1}]} = Chronicle.history(post, limit: 1, offset: 1)
      assert {:ok, []} = Chronicle.history(post, limit: 1, offset: 5)
    end

    test "rejects a page that is not usable", %{post: post} do
      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.history(post, limit: 0)

      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.history(post, offset: -1)

      assert {:error, %Chronicle.Error{reason: :invalid_query}} =
               Chronicle.history(post, limit: 100_000)
    end
  end

  describe "reconstruction fails closed" do
    test "a tombstone is visible in history but is not a record", %{post: post} do
      {:ok, _} = Chronicle.delete(post)

      assert {:ok, [tombstone | _]} = Chronicle.history(Post, post.id)
      assert tombstone.operation == :delete
      assert tombstone.record == nil
      refute tombstone.restorable?

      assert {:error, %Chronicle.Error{reason: :record_deleted}} = Chronicle.at(Post, post.id, [])

      assert {:error, %Chronicle.Error{reason: :record_deleted}} =
               Chronicle.revert(post, version: 3)
    end

    test "an incompatible schema is refused rather than half-loaded", %{repo: repo, post: post} do
      # Simulate the schema gaining a field after the version was written.
      Ecto.Adapters.SQL.query!(
        repo,
        "UPDATE audit_events SET data = replace(CAST(data AS TEXT), ?, ?)",
        ["\"schema_fingerprint\":\"", "\"schema_fingerprint\":\"0"],
        log: false
      )

      assert {:error, %Chronicle.Error{reason: :schema_incompatible}} =
               Chronicle.at(post, version: 1)

      assert {:ok, versions} = Chronicle.history(post)
      assert Enum.all?(versions, &(&1.restorable? == false))
      assert Enum.all?(versions, &match?({:schema_incompatible, _, _}, &1.reconstruction_error))
    end
  end

  describe "revert" do
    test "returns a changeset against the current record and never persists", %{post: post} do
      assert {:ok, changeset} = Chronicle.revert(post, version: 1)
      assert changeset.changes == %{title: "v1"}
      assert changeset.data.id == post.id

      # Nothing was written just by asking.
      assert {:ok, [_, _]} = Chronicle.history(post)
    end

    test "drops the primary key so a revert cannot re-key the record", %{post: post} do
      assert {:ok, changeset} = Chronicle.revert(post, version: 1)
      refute Map.has_key?(changeset.changes, :id)
    end
  end

  describe "lookup by identity" do
    test "accepts a struct or a schema and key", %{post: post} do
      assert {:ok, by_struct} = Chronicle.history(post)
      assert {:ok, by_key} = Chronicle.history(Post, post.id)

      assert Enum.map(by_struct, & &1.version) == Enum.map(by_key, & &1.version)
    end

    test "reports a schema without a primary key" do
      defmodule Keyless do
        use Ecto.Schema
        @primary_key false
        schema "keyless" do
          field :name, :string
        end
      end

      assert {:error, %Chronicle.Error{}} = Chronicle.history(Keyless, "x")
    end
  end
end
