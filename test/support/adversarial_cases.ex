defmodule Chronicle.Test.AdversarialCases do
  @moduledoc """
  The systematic tamper matrix, shared by the SQLite and PostgreSQL suites.

  Every claim in the README's "Chronicle detects" list gets an executable
  counterpart here, plus one case for the documented boundary: a whole-ledger
  rewind is invisible without an externally held checkpoint.

  Field mutations are generated from `Chronicle.Ecto.Schema.Event.content_fields/0`,
  so a new signed column automatically gains a tamper test rather than
  silently going uncovered.
  """

  defmacro __using__(opts) do
    adapter = Keyword.fetch!(opts, :adapter)

    quote do
      use ExUnit.Case, async: false

      use Chronicle

      import Ecto.Query

      alias Chronicle.Ecto.Schema.Event
      alias Chronicle.Test.Databases

      @adapter unquote(adapter)

      # Must precede the generated tests so exclusion applies to them.
      if unquote(adapter) == :postgres, do: @moduletag(:postgres)

      # Reasons that constitute "detected". `:verification_failed` is the
      # catch-all and is deliberately excluded: if a tamper lands there, the
      # error classification needs improving rather than the test loosening.
      @detected [
        :content_tampered,
        :ledger_tampered,
        :sequence_gap,
        :checkpoint_mismatch,
        :unsigned_records_present,
        # An entry naming a key the store cannot resolve is detected, but stays
        # distinct from tampering: an operator who has genuinely lost a
        # historical key needs to tell the two apart.
        :verification_key_missing
      ]

      setup do
        {repo, prefix} = Databases.start!(@adapter)
        Databases.configure!(repo, prefix)
        %{repo: repo, prefix: prefix}
      end

      defp sql!(repo, prefix, statement) do
        Ecto.Adapters.SQL.query!(repo, String.replace(statement, "@", table(prefix)), [],
          log: false
        )
      end

      defp table(nil), do: ""
      defp table(prefix), do: ~s("#{prefix}".)

      # A standalone event, a group with two children, then another standalone
      # event: three ledger entries covering both signed record kinds.
      defp seed! do
        first = Chronicle.record!("standalone.one", %{n: 1}, actor: Chronicle.actor("user", "u1"))

        Chronicle.transaction("unit.of.work", [], fn ->
          Chronicle.record!("unit.step", %{step: 1})
          Chronicle.record!("unit.step", %{step: 2})
          :ok
        end)

        Chronicle.record!("standalone.two", %{n: 2})
        assert {:ok, _} = Chronicle.verify_all()
        first
      end

      defp assert_detected(context \\ "tamper") do
        case Chronicle.verify_all() do
          {:ok, _checkpoints} ->
            flunk("#{context} went undetected")

          {:error, %Chronicle.Error{reason: reason} = error} ->
            assert reason in @detected,
                   "#{context} was detected but classified as #{inspect(reason)}, " <>
                     "cause: #{inspect(error.cause)}"
        end
      end

      test "the fixture verifies before any tampering" do
        seed!()
      end

      # ------------------------------------------------------------------
      # Signed content
      # ------------------------------------------------------------------

      for field <- Chronicle.Ecto.Schema.Event.content_fields() do
        @field field

        test "detects modification of the signed column #{field}", %{repo: repo, prefix: prefix} do
          event = seed!()

          value =
            case @field do
              # A foreign key to the record table: point it at the real group
              # root, which smuggles a signed standalone event into a signed
              # group rather than merely breaking the constraint.
              :group_id -> "'#{group_root_id(repo, prefix)}'"
              field -> tamper_value(Event.__schema__(:type, field), field)
            end

          sql!(
            repo,
            prefix,
            "UPDATE @audit_events SET #{@field} = #{value} WHERE id = '#{event.id}'"
          )

          assert_detected("modifying #{@field}")
        end
      end

      defp group_root_id(repo, prefix) do
        %{rows: [[id]]} =
          sql!(
            repo,
            prefix,
            "SELECT CAST(id AS text) FROM @audit_events WHERE kind = 'group' LIMIT 1"
          )

        id
      end

      defp tamper_value(:string, _field), do: "'audit-met-tampered'"
      defp tamper_value(:binary_id, _field), do: "'11111111-1111-1111-1111-111111111111'"
      defp tamper_value(:integer, _field), do: "9999"
      defp tamper_value(:boolean, field), do: "NOT #{field}"
      defp tamper_value(:utc_datetime_usec, _field), do: "'2020-01-01 00:00:00.000000'"
      defp tamper_value(Chronicle.Ecto.JSON, _field), do: ~s('[{"field":"tampered"}]')
      defp tamper_value(:map, _field), do: ~s('{"tampered":true}')

      # ------------------------------------------------------------------
      # Row-level coverage
      # ------------------------------------------------------------------

      test "detects deletion of a signed record", %{repo: repo, prefix: prefix} do
        event = seed!()
        sql!(repo, prefix, "DELETE FROM @audit_events WHERE id = '#{event.id}'")
        assert_detected("deleting a signed record")
      end

      test "detects an unsigned record appended to the table", %{repo: repo, prefix: prefix} do
        seed!()

        sql!(repo, prefix, """
        INSERT INTO @audit_events
          (id, ledger, ledger_sequence, kind, type, outcome,
           record_version, occurred_at, data, metadata, inserted_at)
        VALUES
          ('22222222-2222-2222-2222-222222222222', 'primary', 99, 'event', 'forged.fact',
           'success', false, '2020-01-01 00:00:00.000000', '{}', '{}',
           '2020-01-01 00:00:00.000000')
        """)

        assert_detected("inserting an unsigned record")
      end

      test "detects removal of a child from a signed group", %{repo: repo, prefix: prefix} do
        seed!()

        sql!(repo, prefix, """
        DELETE FROM @audit_events
        WHERE kind = 'event' AND group_id IS NOT NULL AND type = 'unit.step'
          AND sequence = 2
        """)

        assert_detected("removing a group child")
      end

      test "detects an extra child added to a signed group", %{repo: repo, prefix: prefix} do
        seed!()

        group_id = group_root_id(repo, prefix)

        sql!(repo, prefix, """
        INSERT INTO @audit_events
          (id, ledger, ledger_sequence, kind, group_id, sequence, type, outcome,
           record_version, occurred_at, data, metadata, inserted_at)
        VALUES
          ('33333333-3333-3333-3333-333333333333', 'primary', 2, 'event', '#{group_id}', 3,
           'smuggled.step', 'success', false, '2020-01-01 00:00:00.000000', '{}', '{}',
           '2020-01-01 00:00:00.000000')
        """)

        assert_detected("adding a group child")
      end

      # ------------------------------------------------------------------
      # The chain itself
      # ------------------------------------------------------------------

      for column <- ~w(digest signature previous_digest content_digest key_id) do
        @column column

        test "detects tampering with ledger entry #{column}", %{repo: repo, prefix: prefix} do
          seed!()

          sql!(
            repo,
            prefix,
            "UPDATE @audit_ledger_entries SET #{@column} = 'tampered' WHERE sequence = 2"
          )

          assert_detected("tampering with entry #{@column}")
        end
      end

      test "detects reordering of ledger entries", %{repo: repo, prefix: prefix} do
        seed!()

        sql!(repo, prefix, "UPDATE @audit_ledger_entries SET sequence = 99 WHERE sequence = 1")
        sql!(repo, prefix, "UPDATE @audit_ledger_entries SET sequence = 1 WHERE sequence = 3")
        sql!(repo, prefix, "UPDATE @audit_ledger_entries SET sequence = 3 WHERE sequence = 99")

        assert_detected("reordering ledger entries")
      end

      test "detects a deleted ledger entry", %{repo: repo, prefix: prefix} do
        seed!()
        sql!(repo, prefix, "DELETE FROM @audit_ledger_entries WHERE sequence = 2")
        assert_detected("deleting a ledger entry")
      end

      test "detects a forged ledger head", %{repo: repo, prefix: prefix} do
        seed!()

        sql!(
          repo,
          prefix,
          "UPDATE @audit_ledger_heads SET sequence = 99, digest = 'forged' WHERE ledger = 'primary'"
        )

        assert_detected("forging the ledger head")
      end

      # ------------------------------------------------------------------
      # The documented boundary
      # ------------------------------------------------------------------

      test "a whole-ledger rewind is invisible without an external checkpoint", %{
        repo: repo,
        prefix: prefix
      } do
        seed!()
        assert {:ok, anchor} = Chronicle.checkpoint()

        # Remove the last entry and rewind the head to match: the remaining
        # chain is internally consistent.
        %{rows: [[digest]]} =
          sql!(repo, prefix, "SELECT digest FROM @audit_ledger_entries WHERE sequence = 2")

        sql!(repo, prefix, "DELETE FROM @audit_events WHERE ledger_sequence = 3")
        sql!(repo, prefix, "DELETE FROM @audit_ledger_entries WHERE sequence = 3")

        sql!(
          repo,
          prefix,
          "UPDATE @audit_ledger_heads SET sequence = 2, digest = '#{digest}' WHERE ledger = 'primary'"
        )

        # This is the honest limit of a self-contained ledger.
        assert {:ok, _} = Chronicle.verify_all()

        # An externally held checkpoint is what makes the rewind visible.
        assert {:error, %Chronicle.Error{reason: :checkpoint_mismatch}} =
                 Chronicle.verify_all(:primary, checkpoints: %{"primary" => anchor})
      end

      test "an unmodified store still verifies against its own checkpoint" do
        seed!()
        assert {:ok, anchor} = Chronicle.checkpoint()

        assert {:ok, _} = Chronicle.verify_all(:primary, checkpoints: %{"primary" => anchor})
      end
    end
  end
end
