defmodule Chronicle.EctoTest do
  use ExUnit.Case, async: true

  alias Chronicle.Ecto, as: AuditEcto

  defmodule Widget do
    use Ecto.Schema

    @primary_key {:id, :binary_id, autogenerate: false}
    schema "widgets" do
      field :name, :string
      field :password, :string
      field :count, :integer
      field :payload, :binary
    end
  end

  defmodule PolicyWidget do
    use Ecto.Schema

    use Chronicle.Schema,
      only: [:email, :password_hash, :session_token],
      hash: [:email],
      redact: [:password_hash],
      omit: [:session_token]

    @primary_key {:id, :binary_id, autogenerate: false}
    schema "policy_widgets" do
      field :slug, :string
      field :email, :string
      field :password_hash, :string
      field :session_token, :string
      field :counter, :integer
    end
  end

  test "turns a changeset into a redacted generic event" do
    before = %Widget{id: "46f96c12-82a8-42fa-bff1-c815c27300e9", name: "old", password: "old"}

    changeset =
      Ecto.Changeset.change(before, %{
        name: "new",
        password: "new secret"
      })

    result = Ecto.Changeset.apply_changes(changeset)
    event = AuditEcto.event(:update, changeset, result, actor: %{type: "user", id: "u-1"})

    assert event.type == "ecto.widgets.update"
    assert event.action == "update"
    assert event.subject["type"] == inspect(Widget)
    assert event.subject["id"] == before.id

    assert event.data["ecto"]["changes"] == [
             %{"field" => "name", "from" => "old", "to" => "new"},
             %{
               "field" => "password",
               "from" => "[REDACTED]",
               "to" => "[REDACTED]"
             }
           ]
  end

  test "supports a custom redactor" do
    before = %Widget{id: "46f96c12-82a8-42fa-bff1-c815c27300e9", count: 1}
    changeset = Ecto.Changeset.change(before, %{count: 2})
    result = Ecto.Changeset.apply_changes(changeset)

    [change] =
      AuditEcto.changes(:update, changeset, result,
        redact: fn :count, value -> "number:#{value}" end
      )

    assert change == %{"field" => "count", "from" => "number:1", "to" => "number:2"}
  end

  test "schema policy controls tracked fields and protection strategies" do
    before = %PolicyWidget{
      id: Ecto.UUID.generate(),
      slug: "visible-identity",
      email: "old@example.test",
      password_hash: "old-hash",
      session_token: "old-token",
      counter: 1
    }

    changeset =
      Ecto.Changeset.change(before, %{
        email: "new@example.test",
        password_hash: "new-hash",
        session_token: "new-token",
        counter: 2
      })

    result = Ecto.Changeset.apply_changes(changeset)
    event = AuditEcto.event(:update, changeset, result)

    assert event.subject["id"] == before.id

    assert Enum.map(event.data["ecto"]["changes"], & &1["field"]) == [
             "email",
             "password_hash",
             "session_token"
           ]

    email = Enum.find(event.data["ecto"]["changes"], &(&1["field"] == "email"))
    assert email["from"] =~ ~r/^sha256:[0-9a-f]{64}$/
    assert email["to"] =~ ~r/^sha256:[0-9a-f]{64}$/

    password = Enum.find(event.data["ecto"]["changes"], &(&1["field"] == "password_hash"))
    assert password["from"] == "[REDACTED]"
    assert password["to"] == "[REDACTED]"

    token = Enum.find(event.data["ecto"]["changes"], &(&1["field"] == "session_token"))
    assert token == %{"field" => "session_token"}
  end

  test "schema policy rejects conflicting protection strategies at compilation" do
    module = "Chronicle.InvalidPolicy#{System.unique_integer([:positive])}"

    source = """
    defmodule #{module} do
      use Chronicle.Schema,
        hash: [:email],
        redact: [:email]
    end
    """

    assert_raise ArgumentError, ~r/more than one protection strategy/, fn ->
      Code.compile_string(source)
    end
  end

  test "multi helper adds the domain and audit operations" do
    changeset = Ecto.Changeset.change(%Widget{name: "new"})

    operations =
      Ecto.Multi.new()
      |> Chronicle.Multi.insert(:widget, changeset)
      |> Ecto.Multi.to_list()

    assert [
             {:widget, {:insert, operation_changeset, []}},
             {{:chronicle, :widget}, {:run, _fun}}
           ] = operations

    assert operation_changeset.data == changeset.data
    assert operation_changeset.action == :insert
  end

  test "snapshots round-trip non-UTF8 binary fields and reject schema mismatches" do
    widget = %Widget{
      id: "46f96c12-82a8-42fa-bff1-c815c27300e9",
      name: "binary",
      payload: <<0, 255, 1>>
    }

    snapshot = Chronicle.Ecto.Snapshot.capture(:insert, widget, [])

    assert snapshot["fields"]["payload"] == %{
             "$audit_type" => "binary",
             "base64" => "AP8B"
           }

    assert {:ok, historical} = Chronicle.Ecto.Snapshot.reify(Widget, snapshot)
    assert historical.payload == widget.payload

    incompatible = Map.put(snapshot, "schema_fingerprint", String.duplicate("0", 64))

    assert {:error, {:schema_incompatible, _, _}} =
             Chronicle.Ecto.Snapshot.reify(Widget, incompatible)
  end
end
