defmodule Chronicle.Group.Buffer do
  @moduledoc false

  # One of the few places here that genuinely needs a process. A group
  # accumulates events until it closes, and those events may be raised from
  # tasks running in other processes — so this is shared mutable state with a
  # lifecycle, which is what an `Agent` is for. It is not a queue and not a
  # bottleneck: appends are short and the group is closed by its owner.
  #
  # `closed?` is a correctness guard rather than bookkeeping. The group's child
  # count is signed, so an event appended after the ledger entry was written
  # would make the signed count disagree with the rows on disk, and the group
  # would fail verification ever afterwards. Refusing the late append turns a
  # leaked task into a visible `:group_closed` error at the point of the
  # mistake, instead of a tamper alert months later.

  alias Chronicle.Event

  @spec start_link(Chronicle.Group.t()) :: Agent.on_start()
  def start_link(group) do
    Agent.start_link(fn -> %{group: group, events: [], next_sequence: 1, closed?: false} end)
  end

  @spec append(pid(), Event.t()) :: {:ok, Event.t()} | {:error, :group_closed}
  def append(buffer, %Event{} = event) do
    Agent.get_and_update(buffer, fn
      %{closed?: true} = state ->
        {{:error, :group_closed}, state}

      state ->
        event = Event.put_group(event, state.group.id, state.next_sequence)

        new_state = %{
          state
          | events: [event | state.events],
            next_sequence: state.next_sequence + 1
        }

        {{:ok, event}, new_state}
    end)
  catch
    :exit, _reason -> {:error, :group_closed}
  end

  @spec close(pid()) :: [Event.t()]
  def close(buffer) do
    Agent.get_and_update(buffer, fn state ->
      {Enum.reverse(state.events), %{state | closed?: true}}
    end)
  end
end
