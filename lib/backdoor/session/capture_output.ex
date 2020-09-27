defmodule Backdoor.Session.CaptureOutput do
  @moduledoc false
  use GenServer

  require Logger
  import Backdoor.Session.ViaTuple

  def start_link([session_id, name: name]) do
    GenServer.start_link(__MODULE__, session_id, name: name)
  end

  def set_as_group_leader(live_view_pid, session_id) do
    pid = GenServer.whereis(via_tuple(Backdoor.Session.CaptureOutput, session_id))
    GenServer.cast(via_tuple(__MODULE__, session_id), {:set_live_view_pid, live_view_pid})
    Process.group_leader(self(), pid)
  end

  ## Callbacks

  @impl true
  def init(session_id) do
    {:ok, buffer} = StringIO.open("")

    {:ok, %{session_id: session_id, live_view_pid: nil, buffer: buffer}}
  end

  def handle_cast({:set_live_view_pid, pid}, state) do
    {:noreply, %{state | live_view_pid: pid}}
  end

  # Stolen from Phoenix Proxy author Jose Valim
  # https://github.com/phoenixframework/phoenix/blob/00a022fbbf25a9d0845329161b1bc1a192c2d407/lib/phoenix/code_reloader/proxy.ex
  def handle_info(msg, state) do
    case msg do
      {:io_request, from, reply, {:put_chars, chars}} ->
        put_chars(from, reply, chars, state)

      {:io_request, from, reply, {:put_chars, m, f, as}} ->
        put_chars(from, reply, apply(m, f, as), state)

      {:io_request, from, reply, {:put_chars, _encoding, chars}} ->
        put_chars(from, reply, chars, state)

      {:io_request, from, reply, {:put_chars, _encoding, m, f, as}} ->
        put_chars(from, reply, apply(m, f, as), state)

      {:io_request, _from, _reply, _request} = msg ->
        send(Process.group_leader(), msg)

      _ ->
        Logger.info(
          "[#{__MODULE__} received unexpected message:\n#{inspect(msg)}\nThe message was ignored."
        )

        :ok
    end

    {:noreply, state}
  end

  defp put_chars(from, reply, chars, %{
         live_view_pid: live_view_pid,
         session_id: session_id,
         buffer: buffer
       }) do
    send(Process.group_leader(), {:io_request, from, reply, {:put_chars, chars}})

    StringIO.flush(buffer)
    send(buffer, {:io_request, from, reply, {:put_chars, chars}})
    {_, out} = StringIO.contents(buffer)

    Backdoor.Session.Log.put_log(via_tuple(Backdoor.Session.Log, session_id), {:output, out})

    if live_view_pid do
      send(live_view_pid, {:put_log, {:output, out}})
    end
  end
end
