# godot-supabase
Godot Supabase purely for Google Sign in

### Usage
```
extends Control

func _ready():
	Supabase.auth_succeeded.connect(receiveData)

	var forestLoot: Dictionary = await Supabase.query_database("Loots", "name", "Forest", "loot")
	print(forestLoot)

	var allLoot = await Supabase.query_all_database("Loots", "loot")
	print(allLoot)

func receiveData(data):
	var user = data["user"]
	var _access_token = data["access_token"]
	var _refresh_token = data["refresh_token"]

	print("ID: ", user["id"])
	print("Email: ", user["email"])
	print("Name: ", user.get("user_metadata", {}).get("full_name", ""))
	print("Avatar: ", user.get("user_metadata", {}).get("avatar_url", ""))

	var userData = await Supabase.data_received
	print(userData)

func _on_button_pressed() -> void:
	Supabase.init()
```
