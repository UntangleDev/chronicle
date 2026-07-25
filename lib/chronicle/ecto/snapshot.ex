if Code.ensure_loaded?(Ecto.Changeset) do
  defmodule Chronicle.Ecto.Snapshot do
    @moduledoc false

    # Captures the complete resulting row on every audited write, rather than a
    # delta against the previous one. Reconstructing a past state then reads one
    # version instead of replaying every mutation since the record was created,
    # which is what keeps a historical read bounded and independent of how much
    # has happened since. The cost is storage, and it is paid deliberately.
    #
    # Fields are captured in sorted order for the same reason maps are sorted in
    # `Chronicle.Canonical`: the snapshot is signed, so its layout has to be a
    # function of its contents and nothing else.
    #
    # ## `complete` is a claim, and `missing_fields` is its receipt
    #
    # Protection is the only thing that may withhold a field. When it does, the
    # snapshot records which fields were withheld and marks itself incomplete,
    # and reconstruction then refuses with `:snapshot_incomplete` naming them.
    #
    # It would be easy, and much friendlier, to substitute a placeholder and
    # hand back a struct. That is precisely what must not happen: a
    # reconstruction that looks successful but contains an invented value is
    # indistinguishable from a real one at the call site, and `Chronicle.revert/2`
    # would write it back into the live record as though it were data. Refusing
    # is the only answer that cannot silently corrupt the thing it is restoring.

    alias Chronicle.{Canonical, Digest, Erasable, Erasure, Redaction, Sensitive, Value}

    @format 1

    @spec subject(struct()) :: map()
    def subject(%schema{} = record) do
      %{"type" => inspect(schema), "id" => primary_key!(schema, record)}
    end

    @spec subject(module(), term()) :: map()
    def subject(schema, id) when is_atom(schema) do
      %{"type" => inspect(schema), "id" => normalize_key_input!(schema, id)}
    end

    @spec key_hash(map()) :: String.t()
    defdelegate key_hash(reference), to: Chronicle.Reference, as: :digest

    @spec capture(:insert | :update | :delete, struct(), keyword()) :: map()
    def capture(operation, %schema{} = record, opts)
        when operation in [:insert, :update, :delete] do
      redactor = Redaction.ecto_redactor(schema, Keyword.put(opts, :record, record))
      value_policy = Redaction.compile(Keyword.put(opts, :schema, schema))

      # Every persisted field is captured; only protection can withhold one.
      # `only` and `except` select which changes are worth reporting, not what
      # a version has to contain to be reconstructable — excluding a noisy
      # timestamp from diffs should not disable time travel for the schema.
      {fields, missing_fields} =
        schema.__schema__(:fields)
        |> Enum.sort_by(&Atom.to_string/1)
        |> Enum.reduce({%{}, []}, fn field, {captured, missing} ->
          case restorable_value(redactor, value_policy, field, Map.get(record, field)) do
            {:ok, normalized} ->
              {Map.put(captured, Atom.to_string(field), normalized), missing}

            :protected ->
              {captured, [field | missing]}
          end
        end)

      missing_fields = missing_fields |> Enum.reverse() |> Enum.map(&Atom.to_string/1)

      %{
        "format" => @format,
        "state" => if(operation == :delete, do: "deleted", else: "present"),
        "schema" => inspect(schema),
        "source" => schema.__schema__(:source),
        "schema_fingerprint" => fingerprint(schema),
        "complete" => missing_fields == [],
        "missing_fields" => missing_fields,
        "fields" => fields
      }
    end

    @spec fingerprint(module()) :: String.t()
    def fingerprint(schema) when is_atom(schema) do
      description =
        schema.__schema__(:fields)
        |> Enum.sort_by(&Atom.to_string/1)
        |> Enum.map(fn field ->
          {Atom.to_string(field), inspect(schema.__schema__(:type, field))}
        end)

      {:audit_ecto_schema_v1, inspect(schema), schema.__schema__(:source), description}
      |> Canonical.encode()
      |> Digest.sha256()
    end

    @spec reify(module(), map()) :: {:ok, struct()} | {:error, term()}
    def reify(schema, snapshot) when is_atom(schema) and is_map(snapshot) do
      with :ok <- compatible?(schema, snapshot),
           :ok <- complete?(snapshot),
           :ok <- present?(snapshot),
           {:ok, attributes} <- load_attributes(schema, map_value(snapshot, "fields")) do
        record =
          schema
          |> struct(attributes)
          |> Ecto.put_meta(state: :loaded, source: schema.__schema__(:source))

        {:ok, record}
      end
    end

    @spec attributes(module(), map()) :: {:ok, map()} | {:error, term()}
    def attributes(schema, snapshot) when is_atom(schema) and is_map(snapshot) do
      with :ok <- compatible?(schema, snapshot),
           :ok <- complete?(snapshot),
           :ok <- present?(snapshot),
           {:ok, attributes} <- load_attributes(schema, map_value(snapshot, "fields")) do
        {:ok, attributes}
      end
    end

    defp primary_key!(schema, record) do
      fields = schema.__schema__(:primary_key)

      if fields == [] do
        raise ArgumentError,
              "#{inspect(schema)} has no primary key; audited Ecto versions require stable identity"
      end

      fields
      |> Enum.map(fn field ->
        value = Map.get(record, field)

        if is_nil(value) do
          raise ArgumentError,
                "#{inspect(schema)} primary key #{inspect(field)} is nil after persistence"
        end

        {Atom.to_string(field), Value.canonical(value)}
      end)
      |> collapse()
    end

    # A single-column key is its own value. Wrapping it in a map would make
    # every reference read `subject.id.id`, and would push identity through the
    # composite-key digest for no gain.
    defp collapse([{_field, value}]), do: value
    defp collapse(pairs), do: Map.new(pairs)

    defp normalize_key_input!(schema, id) do
      fields = schema.__schema__(:primary_key)

      cond do
        fields == [] ->
          raise ArgumentError,
                "#{inspect(schema)} has no primary key; audited Ecto versions require stable identity"

        length(fields) == 1 and not is_map(id) and not Keyword.keyword?(List.wrap(id)) ->
          Value.canonical(id)

        is_map(id) or (is_list(id) and Keyword.keyword?(id)) ->
          values = if is_map(id), do: id, else: Map.new(id)

          fields
          |> Enum.map(fn field ->
            case fetch_key(values, field) do
              {:ok, value} when not is_nil(value) ->
                {Atom.to_string(field), Value.canonical(value)}

              _ ->
                raise ArgumentError,
                      "missing primary key #{inspect(field)} for #{inspect(schema)}"
            end
          end)
          |> collapse()

        true ->
          raise ArgumentError,
                "#{inspect(schema)} has a composite primary key; pass a map or keyword list"
      end
    end

    defp restorable_value(_redactor, _policy, _field, nil), do: {:ok, nil}

    defp restorable_value(redactor, policy, field, value) do
      original = Value.canonical(value)

      case redactor.(field, value) do
        %Sensitive{} ->
          :protected

        %Erasable{} = erasable ->
          {:ok, Value.normalize(erasable, policy)}

        protected ->
          normalized = Value.normalize(protected, policy)
          if normalized == original, do: {:ok, normalized}, else: :protected
      end
    end

    defp compatible?(schema, snapshot) do
      stored_schema = map_value(snapshot, "schema")
      stored_fingerprint = map_value(snapshot, "schema_fingerprint")
      current_fingerprint = fingerprint(schema)

      cond do
        map_value(snapshot, "format") != @format ->
          {:error, {:unsupported_snapshot_format, map_value(snapshot, "format")}}

        stored_schema != inspect(schema) ->
          {:error, {:snapshot_schema_mismatch, stored_schema, inspect(schema)}}

        stored_fingerprint != current_fingerprint ->
          {:error, {:schema_incompatible, stored_fingerprint, current_fingerprint}}

        true ->
          :ok
      end
    end

    defp complete?(snapshot) do
      if map_value(snapshot, "complete") == true do
        :ok
      else
        {:error, {:snapshot_incomplete, missing_fields(snapshot)}}
      end
    end

    defp present?(snapshot) do
      case map_value(snapshot, "state") do
        "present" -> :ok
        "deleted" -> {:error, :record_deleted}
        state -> {:error, {:invalid_snapshot_state, state}}
      end
    end

    defp load_attributes(schema, fields) when is_map(fields) do
      schema.__schema__(:fields)
      |> Enum.reduce_while({:ok, %{}}, fn field, {:ok, attributes} ->
        key = Atom.to_string(field)

        if Map.has_key?(fields, key) or Map.has_key?(fields, field) do
          stored_value = Map.get(fields, key, Map.get(fields, field))
          type = schema.__schema__(:type, field)

          with {:ok, value} <- decode_value(stored_value),
               {:ok, loaded} <- Ecto.Type.cast(type, value) do
            {:cont, {:ok, Map.put(attributes, field, loaded)}}
          else
            :error -> {:halt, {:error, {:snapshot_field_invalid, field, stored_value}}}
            {:error, {:erasure_key_unavailable, _key_id} = reason} -> {:halt, {:error, reason}}
            {:error, reason} -> {:halt, {:error, {:snapshot_field_invalid, field, reason}}}
          end
        else
          {:halt, {:error, {:snapshot_incomplete, [field]}}}
        end
      end)
    end

    defp load_attributes(_schema, fields),
      do: {:error, {:invalid_snapshot_fields, fields}}

    defp missing_fields(snapshot) do
      snapshot
      |> map_value("missing_fields")
      |> List.wrap()
      |> Enum.map(&safe_field/1)
    end

    defp safe_field(field) when is_atom(field), do: field

    defp safe_field(field) when is_binary(field) do
      String.to_existing_atom(field)
    rescue
      ArgumentError -> field
    end

    defp fetch_key(values, field) do
      case Map.fetch(values, field) do
        {:ok, value} -> {:ok, value}
        :error -> Map.fetch(values, Atom.to_string(field))
      end
    end

    defp map_value(map, key) do
      Map.get(map, key, Map.get(map, safe_existing_atom(key)))
    end

    defp safe_existing_atom(value) do
      String.to_existing_atom(value)
    rescue
      ArgumentError -> nil
    end

    defp decode_value(%{"$audit_type" => "binary", "base64" => encoded} = value)
         when map_size(value) == 2 do
      case Base.decode64(encoded) do
        {:ok, binary} -> {:ok, binary}
        :error -> {:error, :invalid_base64_binary}
      end
    end

    defp decode_value(value) when is_map(value) do
      if Erasure.envelope?(value) do
        with {:ok, decrypted} <- Erasure.decrypt(value) do
          decode_value(decrypted)
        end
      else
        Enum.reduce_while(value, {:ok, %{}}, fn {key, nested}, {:ok, decoded} ->
          case decode_value(nested) do
            {:ok, decoded_nested} -> {:cont, {:ok, Map.put(decoded, key, decoded_nested)}}
            {:error, _reason} = error -> {:halt, error}
          end
        end)
      end
    end

    defp decode_value(value) when is_list(value) do
      Enum.reduce_while(value, {:ok, []}, fn nested, {:ok, decoded} ->
        case decode_value(nested) do
          {:ok, decoded_nested} -> {:cont, {:ok, [decoded_nested | decoded]}}
          {:error, _reason} = error -> {:halt, error}
        end
      end)
      |> case do
        {:ok, decoded} -> {:ok, Enum.reverse(decoded)}
        error -> error
      end
    end

    defp decode_value(value), do: {:ok, value}
  end
end
