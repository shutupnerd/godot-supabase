extends Node

const SUPABASE_URL := "" #ENTER
const SUPABASE_KEY := "" # ENTER

const LOCAL_PORT := 50505
const REDIRECT_URI := "http://localhost:50505"
const POLL_TIMEOUT_SEC := 120.0

const USER_DATA = "LiveData"

var _server := TCPServer.new()
var _elapsed := 0.0

var session := {}

signal data_received(data: Dictionary)
signal query_received(data: Variant)
signal rpc_received(data: Variant)

signal auth_succeeded(session: Dictionary)
signal auth_failed(reason: String)

# ── Lifecycle ────────────────────────────────────────────────────────────────

func _ready() -> void:
	set_process(false)

func _process(delta: float) -> void:
	_elapsed += delta
	if _elapsed >= POLL_TIMEOUT_SEC:
		_shutdown()
		auth_failed.emit("Timed out waiting for browser redirect")
		return

	if not _server.is_connection_available():
		return

	var peer: StreamPeerTCP = _server.take_connection()
	var raw := _read_peer(peer)

	if raw.is_empty():
		peer.disconnect_from_host()
		_shutdown()
		auth_failed.emit("Empty request from browser")
		return

	var first_line := raw.split("\r\n")[0]
	var parts := first_line.split(" ")

	if parts.size() < 2:
		peer.disconnect_from_host()
		_shutdown()
		auth_failed.emit("Malformed HTTP request")
		return

	var method := parts[0] # GET / POST
	var request_path := parts[1] # e.g. /?code=... or /callback

	if method == "POST" and "/callback" in request_path:
		# Fragment relay round-trip: tokens are in the POST body
		_send_html_response(peer, _success_page())
		peer.disconnect_from_host()
		_shutdown()
		_handle_fragment_post(raw)

	elif "code=" in request_path:
		# PKCE: auth code in query string
		_send_html_response(peer, _success_page())
		peer.disconnect_from_host()
		_shutdown()
		var query := request_path.split("?")[-1]
		var params := _parse_query(query)
		_exchange_code(params["code"])

	elif "access_token=" in request_path:
		# Implicit: tokens directly in query string
		_send_html_response(peer, _success_page())
		peer.disconnect_from_host()
		_shutdown()
		var query := request_path.split("?")[-1]
		_finalise_session(_parse_query(query))

	else:
		# Fragment flow: browser landed here with hash — serve relay page.
		# Server stays open to receive the follow-up POST /callback.
		_send_html_response(peer, _fragment_relay_page())
		peer.disconnect_from_host()
		# Do NOT shutdown — wait for the POST /callback next iteration.

# ── Public entry point ───────────────────────────────────────────────────────

func init() -> void:
	if _server.is_listening():
		return

	var err := _server.listen(LOCAL_PORT)
	if err != OK:
		push_error("TCPServer failed on port %d (err %d)" % [LOCAL_PORT, err])
		auth_failed.emit("Could not open local server")
		return

	var auth_url := (
		SUPABASE_URL
		+"/auth/v1/authorize"
		+"?provider=google"
		+"&redirect_to=" + REDIRECT_URI.uri_encode()
	)

	OS.shell_open(auth_url)
	_elapsed = 0.0
	set_process(true)

# ── Token exchange (PKCE) ────────────────────────────────────────────────────

func _exchange_code(code: String) -> void:
	var http := HTTPRequest.new()
	add_child(http)
	http.request_completed.connect(_on_token_response.bind(http))
	http.request(
		SUPABASE_URL + "/auth/v1/token?grant_type=pkce",
		PackedStringArray(["Content-Type: application/json", "apikey: " + SUPABASE_KEY]),
		HTTPClient.METHOD_POST,
		JSON.stringify({"auth_code": code, "redirect_uri": REDIRECT_URI})
	)

func _on_token_response(_result: int, _code: int, _headers: PackedStringArray,
		body: PackedByteArray, http: HTTPRequest) -> void:
	http.queue_free()
	var parsed: Variant = JSON.parse_string(body.get_string_from_utf8())
	if not parsed is Dictionary:
		auth_failed.emit("Token exchange: bad JSON")
		return
	_finalise_session(parsed)

# ── Fragment POST handler ────────────────────────────────────────────────────

func _handle_fragment_post(raw: String) -> void:
	var sections := raw.split("\r\n\r\n")
	if sections.size() < 2 or sections[1].is_empty():
		auth_failed.emit("Fragment relay: empty body")
		return
	_finalise_session(_parse_query(sections[1]))

# ── Session + user fetch ─────────────────────────────────────────────────────

func _finalise_session(params: Dictionary) -> void:
	if not params.has("access_token"):
		auth_failed.emit("No access_token in response: " + str(params))
		return
	session = {
		"access_token": params.get("access_token", ""),
		"refresh_token": params.get("refresh_token", ""),
		"expires_in": params.get("expires_in", 3600),
		"token_type": params.get("token_type", "bearer"),
	}
	_fetch_user()

func _fetch_user() -> void:
	var http := HTTPRequest.new()
	add_child(http)
	http.request_completed.connect(_on_user_response.bind(http))
	http.request(
		SUPABASE_URL + "/auth/v1/user",
		PackedStringArray([
			"apikey: " + SUPABASE_KEY,
			"Authorization: Bearer " + session["access_token"],
		])
	)

func _on_user_response(_result: int, _code: int, _headers: PackedStringArray,
		body: PackedByteArray, http: HTTPRequest) -> void:
	http.queue_free()
	var parsed: Variant = JSON.parse_string(body.get_string_from_utf8())
	if parsed is Dictionary:
		session["user"] = parsed
	var id = parsed.get("id")
	var token = session.get("access_token")
	get_user_data(id, token)
	auth_succeeded.emit(session)

# ── Helpers ──────────────────────────────────────────────────────────────────

func _read_peer(peer: StreamPeerTCP) -> String:
	var deadline := Time.get_ticks_msec() + 2000
	var raw := ""
	while Time.get_ticks_msec() < deadline:
		peer.poll()
		var avail := peer.get_available_bytes()
		if avail > 0:
			raw += peer.get_string(avail)
			if "\r\n\r\n" in raw:
				break
		else:
			OS.delay_msec(10)
	return raw

func _send_html_response(peer: StreamPeerTCP, html: String) -> void:
	var bytes := html.to_utf8_buffer()
	var response := (
		"HTTP/1.1 200 OK\r\n"
		+"Content-Type: text/html; charset=utf-8\r\n"
		+"Content-Length: %d\r\n" % bytes.size()
		+"Connection: close\r\n"
		+"\r\n"
	)
	peer.put_data(response.to_utf8_buffer())
	peer.put_data(bytes)

func _parse_query(query: String) -> Dictionary:
	var result := {}
	for pair in query.split("&"):
		var kv := pair.split("=", true) # true = allow empty values
		if kv.size() >= 1 and not kv[0].is_empty():
			result[kv[0]] = kv[1].uri_decode() if kv.size() == 2 else ""
	return result

func get_user_data(user_id: String, access_token: String):
	var http := HTTPRequest.new()
	add_child(http)
	
	# Connect the signal to handle the data once it arrives
	http.request_completed.connect(func(_result, _response_code, _headers, body):
		var response=JSON.parse_string(body.get_string_from_utf8())
		http.queue_free()

		data_received.emit(response)
	)

	# We filter by user_id so we only get OUR specific row
	var url = SUPABASE_URL + "/rest/v1/" + USER_DATA + "?user_id=eq." + user_id
	
	var request_headers = [
		"apikey: " + SUPABASE_KEY,
		"Authorization: Bearer " + access_token,
		"Content-Type: application/json"
	]

	http.request(url, request_headers, HTTPClient.METHOD_GET)

func refresh_access_token(stored_refresh_token: String):
	var http := HTTPRequest.new()
	add_child(http)
	
	http.request_completed.connect(func(_result, response_code, _headers, body):
		var response=JSON.parse_string(body.get_string_from_utf8())
		
		if response_code == 200:
			auth_succeeded.emit(response)
		else:
			print("Refresh failed. User must log in again.")
			#DirAccess.remove_absolute("user://session.json")
			
		http.queue_free()
	)

	var payload = JSON.stringify({
		"refresh_token": stored_refresh_token
	})

	var headers = [
		"apikey: " + SUPABASE_KEY,
		"Content-Type: application/json"
	]

	http.request(
		SUPABASE_URL + "/auth/v1/token?grant_type=refresh_token",
		headers,
		HTTPClient.METHOD_POST,
		payload
	)

func rpc_call(rpcName: String, access_token="", args: Dictionary = {}):
	var http := HTTPRequest.new()
	add_child(http)
	
	var url = SUPABASE_URL + "/rest/v1/rpc/" + rpcName
	var payload = JSON.stringify(args)
	
	var token_to_use = access_token if access_token != "" else SUPABASE_KEY

	var headers = [
		"apikey: " + SUPABASE_KEY,
		"Authorization: Bearer " + token_to_use,
		"Content-Type: application/json"
	]
	
	http.request(url, headers, HTTPClient.METHOD_POST, payload)
	
	var result = await http.request_completed
	var body = JSON.parse_string(result[3].get_string_from_utf8())

	rpc_received.emit(body)
	http.queue_free()

	return rpc_received

# AWAITS!!
# database: the table name (e.g., "LiveData")
# key_name: the column name to filter by (e.g., "user_id")
# key_value: the value to search for
func query_database(database: String, column_name: String, key_value: String, value: String, access_token: String = ""):
	var http := HTTPRequest.new()
	add_child(http)
	
	http.request_completed.connect(func(_result, response_code, _headers, body):
		var response: Array = JSON.parse_string(body.get_string_from_utf8())
		
		if response_code == 200:
			var lootFirst: Dictionary = response.front()
			var requested: Dictionary = lootFirst.get(value)
			query_received.emit(requested)
		else:
			print("Query Error: ", response_code, " - ", response)
			
		http.queue_free()
	)

	var auth_header = "Bearer " + (access_token if access_token != "" else SUPABASE_KEY)
	var url = SUPABASE_URL + "/rest/v1/" + database + "?" + column_name + "=eq." + key_value
	
	var request_headers = [
		"apikey: " + SUPABASE_KEY,
		"Authorization: " + auth_header,
		"Content-Type: application/json"
	]

	http.request(url, request_headers, HTTPClient.METHOD_GET)

	return query_received

func query_all_database(database: String, value: String):
	var http := HTTPRequest.new()
	add_child(http)
	
	var list = []

	http.request_completed.connect(func(_result, response_code, _headers, body):
		var response=JSON.parse_string(body.get_string_from_utf8())
		
		if response_code == 200 and response is Array:
			for item: Dictionary in response:
				var loot=item.get(value)
				list.append(loot)
			query_received.emit(list)
		else:
			push_error("Failed to cache loots: ", response)
		
		http.queue_free()
	)

	# Note: No filters in the URL = get all rows
	var url = SUPABASE_URL + "/rest/v1/" + database
	var headers = [
		"apikey: " + SUPABASE_KEY,
		"Authorization: Bearer " + SUPABASE_KEY
	]

	http.request(url, headers, HTTPClient.METHOD_GET)

	return query_received

func _shutdown() -> void:
	_server.stop()
	set_process(false)
	_elapsed = 0.0

# ── HTML pages ───────────────────────────────────────────────────────────────

func _fragment_relay_page() -> String:
	return """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Signing in...</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
	font-family: system-ui, sans-serif;
	background: #0f0f0f;
	color: #fff;
	display: flex;
	align-items: center;
	justify-content: center;
	height: 100vh;
  }
  .card {
	text-align: center;
	padding: 2.5rem 3rem;
	background: #1a1a1a;
	border-radius: 12px;
	border: 1px solid #2a2a2a;
  }
  .spinner {
	width: 36px; height: 36px;
	border: 3px solid #333;
	border-top-color: #4ade80;
	border-radius: 50%;
	animation: spin 0.7s linear infinite;
	margin: 0 auto 1.2rem;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  h2 { font-size: 1.1rem; font-weight: 500; color: #ccc; }
</style>
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h2>Completing sign-in...</h2>
</div>
<script>
  var hash = window.location.hash.substring(1);
  fetch('/callback', {
	method: 'POST',
	headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
	body: hash
  }).then(function() {
	document.querySelector('h2').innerText = 'Signed in! You can close this tab.';
	document.querySelector('.spinner').style.display = 'none';
  }).catch(function() {
	document.querySelector('h2').innerText = 'Something went wrong. Please retry.';
  });
</script>
</body>
</html>"""

func _success_page() -> String:
	return """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Signed in</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
	font-family: system-ui, sans-serif;
	background: #0f0f0f;
	color: #fff;
	display: flex;
	align-items: center;
	justify-content: center;
	height: 100vh;
  }
  .card {
	text-align: center;
	padding: 2.5rem 3rem;
	background: #1a1a1a;
	border-radius: 12px;
	border: 1px solid #2a2a2a;
  }
  .check {
	font-size: 2.5rem;
	margin-bottom: 1rem;
  }
  h2 { font-size: 1.1rem; font-weight: 500; color: #ccc; }
  p  { margin-top: 0.5rem; font-size: 0.85rem; color: #555; }
</style>
</head>
<body>
<div class="card">
  <div class="check">✅</div>
  <h2>You're signed in!</h2>
  <p>You can close this tab and return to the game.</p>
</div>
</body>
</html>"""
