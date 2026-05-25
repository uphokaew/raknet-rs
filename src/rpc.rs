//! SA-MP and open.mp RPC and Synchronization Packet IDs.
//!
//! A comprehensive catalog of network identifiers parsed from the C++ headers.

// --- RPC Identifiers (Remote Procedure Calls) ---

/// Sent to add a class to class selection.
pub const RPC_SET_SPAWN_INFO: u8 = 68;
/// Request by player to spawn.
pub const RPC_PLAYER_REQUEST_SPAWN: u8 = 129;
/// Respawn response/action.
pub const RPC_PLAYER_REQUEST_SPAWN_RESPONSE: u8 = 129;
pub const RPC_IMMEDIATELY_SPAWN_PLAYER: u8 = 129;

/// Show an actor for a player.
pub const RPC_SHOW_ACTOR_FOR_PLAYER: u8 = 171;
/// Hide an actor for a player.
pub const RPC_HIDE_ACTOR_FOR_PLAYER: u8 = 172;
/// Play actor animation.
pub const RPC_APPLY_ACTOR_ANIMATION_FOR_PLAYER: u8 = 173;
/// Clear actor animations.
pub const RPC_CLEAR_ACTOR_ANIMATIONS_FOR_PLAYER: u8 = 174;
/// Set actor rotation.
pub const RPC_SET_ACTOR_FACING_ANGLE_FOR_PLAYER: u8 = 175;
/// Set actor position.
pub const RPC_SET_ACTOR_POS_FOR_PLAYER: u8 = 176;
/// Set actor health.
pub const RPC_SET_ACTOR_HEALTH_FOR_PLAYER: u8 = 178;
/// Event when player damages actor.
pub const RPC_ON_PLAYER_DAMAGE_ACTOR: u8 = 177;

/// Set a checkpoint.
pub const RPC_SET_CHECKPOINT: u8 = 107;
/// Hide/disable a checkpoint.
pub const RPC_DISABLE_CHECKPOINT: u8 = 37;
/// Set a race checkpoint.
pub const RPC_SET_RACE_CHECKPOINT: u8 = 38;
/// Hide/disable a race checkpoint.
pub const RPC_DISABLE_RACE_CHECKPOINT: u8 = 39;

/// Request class selection.
pub const RPC_PLAYER_REQUEST_CLASS: u8 = 128;
pub const RPC_PLAYER_REQUEST_CLASS_RESPONSE: u8 = 128;

/// Handshake connection.
pub const RPC_PLAYER_CONNECT: u8 = 25;
pub const RPC_NPC_CONNECT: u8 = 54;
pub const RPC_PLAYER_JOIN: u8 = 137;
pub const RPC_PLAYER_QUIT: u8 = 138;
pub const RPC_PLAYER_INIT: u8 = 139;

/// Give player weapon.
pub const RPC_GIVE_PLAYER_WEAPON: u8 = 22;
/// Clear player weapons.
pub const RPC_RESET_PLAYER_WEAPONS: u8 = 21;
/// Force player to equip weapon.
pub const RPC_SET_PLAYER_ARMED_WEAPON: u8 = 67;
/// Show text above player head.
pub const RPC_SET_PLAYER_CHAT_BUBBLE: u8 = 59;
/// Spawn player to other client's stream.
pub const RPC_PLAYER_STREAM_IN: u8 = 32;
/// Remove player from other client's stream.
pub const RPC_PLAYER_STREAM_OUT: u8 = 163;
/// Rename player.
pub const RPC_SET_PLAYER_NAME: u8 = 11;

/// Chat message sent by server to client.
pub const RPC_SEND_CLIENT_MESSAGE: u8 = 93;
/// Chat message sent by client to server.
pub const RPC_PLAYER_REQUEST_CHAT_MESSAGE: u8 = 101;
pub const RPC_PLAYER_CHAT_MESSAGE: u8 = 101;

/// Send command message (e.g. `/mycommand`).
pub const RPC_PLAYER_REQUEST_COMMAND_MESSAGE: u8 = 50;
pub const RPC_PLAYER_COMMAND_MESSAGE: u8 = 50;

/// Add kill feed entry.
pub const RPC_SEND_DEATH_MESSAGE: u8 = 55;
/// Update clock time.
pub const RPC_SEND_GAME_TIME_UPDATE: u8 = 60;
/// Change player weather.
pub const RPC_SET_PLAYER_WEATHER: u8 = 152;
/// Set boundaries of map.
pub const RPC_SET_WORLD_BOUNDS: u8 = 17;
/// Set player tag and marker color.
pub const RPC_SET_PLAYER_COLOR: u8 = 72;
/// Set player position.
pub const RPC_SET_PLAYER_POSITION: u8 = 12;

/// Move player camera.
pub const RPC_SET_PLAYER_CAMERA_POSITION: u8 = 157;
pub const RPC_SET_PLAYER_CAMERA_LOOK_AT: u8 = 158;
pub const RPC_SET_PLAYER_CAMERA_BEHIND_PLAYER: u8 = 162;
pub const RPC_INTERPOLATE_CAMERA: u8 = 82;
pub const RPC_ATTACH_CAMERA_TO_OBJECT: u8 = 81;

/// Teleport player finding ground height.
pub const RPC_SET_PLAYER_POSITION_FIND_Z: u8 = 13;
/// Rotate player.
pub const RPC_SET_PLAYER_FACING_ANGLE: u8 = 19;
/// Set player team ID.
pub const RPC_SET_PLAYER_TEAM: u8 = 69;
/// Set player fighting style.
pub const RPC_SET_PLAYER_FIGHTING_STYLE: u8 = 89;
/// Set weapon skill level.
pub const RPC_SET_PLAYER_SKILL_LEVEL: u8 = 34;
/// Set player skin/model.
pub const RPC_SET_PLAYER_SKIN: u8 = 153;
/// Set player health.
pub const RPC_SET_PLAYER_HEALTH: u8 = 14;
/// Set player armour.
pub const RPC_SET_PLAYER_ARMOUR: u8 = 66;
/// Perform special action (dancing, smoking, etc.).
pub const RPC_SET_PLAYER_SPECIAL_ACTION: u8 = 88;
/// Set velocity/force.
pub const RPC_SET_PLAYER_VELOCITY: u8 = 90;
/// Play animation on player.
pub const RPC_APPLY_PLAYER_ANIMATION: u8 = 86;
/// Clear player animations.
pub const RPC_CLEAR_PLAYER_TASKS: u8 = 87;
/// Control player movement.
pub const RPC_TOGGLE_PLAYER_CONTROLLABLE: u8 = 15;
/// Enter spectator mode.
pub const RPC_TOGGLE_PLAYER_SPECTATING: u8 = 124;
/// Play audio file or standard sound.
pub const RPC_PLAYER_PLAY_SOUND: u8 = 16;
/// Give cash.
pub const RPC_GIVE_PLAYER_MONEY: u8 = 18;
/// Reset cash.
pub const RPC_RESET_PLAYER_MONEY: u8 = 20;
/// Set current time.
pub const RPC_SET_PLAYER_TIME: u8 = 29;
/// Show/hide game clock.
pub const RPC_TOGGLE_PLAYER_CLOCK: u8 = 30;
/// Event when player dies.
pub const RPC_ON_PLAYER_DEATH: u8 = 53;
pub const RPC_PLAYER_DEATH: u8 = 166;
/// Track camera target.
pub const RPC_ON_PLAYER_CAMERA_TARGET: u8 = 168;
/// Set shop interior.
pub const RPC_SET_PLAYER_SHOP_NAME: u8 = 33;
/// Set player camera drunk shaking.
pub const RPC_SET_PLAYER_DRUNK_LEVEL: u8 = 35;
/// Play web URL stream (e.g. radio).
pub const RPC_PLAY_AUDIO_STREAM_FOR_PLAYER: u8 = 41;
/// Stop web URL stream.
pub const RPC_STOP_AUDIO_STREAM_FOR_PLAYER: u8 = 42;
/// Set weapon ammo.
pub const RPC_SET_PLAYER_AMMO: u8 = 145;
/// Synchronize tab score table.
pub const RPC_SEND_PLAYER_SCORES_AND_PINGS: u8 = 155;
pub const RPC_ON_PLAYER_REQUEST_SCORES_AND_PINGS: u8 = 155;
/// Delete standard map building for player.
pub const RPC_REMOVE_BUILDING_FOR_PLAYER: u8 = 43;
/// Spawn an explosion.
pub const RPC_CREATE_EXPLOSION: u8 = 79;
/// Set player interior ID.
pub const RPC_SET_PLAYER_INTERIOR: u8 = 156;
/// Set wanted stars.
pub const RPC_SET_PLAYER_WANTED_LEVEL: u8 = 133;
/// Toggle cinematic widescreen.
pub const RPC_TOGGLE_WIDESCREEN: u8 = 111;
/// Event when player damages/takes damage.
pub const RPC_ON_PLAYER_GIVE_TAKE_DAMAGE: u8 = 115;
/// Event when interior changes.
pub const RPC_ON_PLAYER_INTERIOR_CHANGE: u8 = 118;
/// Track camera targets.
pub const RPC_SET_PLAYER_CAMERA_TARGETING: u8 = 170;
/// Send message to police console.
pub const RPC_PLAY_CRIME_REPORT: u8 = 112;

/// Show a dialog box.
pub const RPC_SHOW_DIALOG: u8 = 61;
/// Event when player interacts with dialog.
pub const RPC_ON_PLAYER_DIALOG_RESPONSE: u8 = 62;

/// Show gang zone on radar.
pub const RPC_SHOW_GANG_ZONE: u8 = 108;
/// Hide gang zone on radar.
pub const RPC_HIDE_GANG_ZONE: u8 = 120;
/// Flash gang zone.
pub const RPC_FLASH_GANG_ZONE: u8 = 121;
/// Stop flashing gang zone.
pub const RPC_STOP_FLASH_GANG_ZONE: u8 = 85;

/// Initialize a menu.
pub const RPC_PLAYER_INIT_MENU: u8 = 76;
/// Show menu.
pub const RPC_PLAYER_SHOW_MENU: u8 = 77;
/// Hide menu.
pub const RPC_PLAYER_HIDE_MENU: u8 = 78;
/// Event when menu row is selected.
pub const RPC_ON_PLAYER_SELECTED_MENU_ROW: u8 = 132;
/// Event when player exits menu.
pub const RPC_ON_PLAYER_EXITED_MENU: u8 = 140;

/// Set texture/color of player object.
pub const RPC_SET_PLAYER_OBJECT_MATERIAL: u8 = 84;
/// Create object.
pub const RPC_CREATE_OBJECT: u8 = 44;
/// Destroy object.
pub const RPC_DESTROY_OBJECT: u8 = 47;
/// Move object.
pub const RPC_MOVE_OBJECT: u8 = 99;
/// Stop moving object.
pub const RPC_STOP_OBJECT: u8 = 122;
/// Set object position.
pub const RPC_SET_OBJECT_POSITION: u8 = 45;
/// Set object rotation.
pub const RPC_SET_OBJECT_ROTATION: u8 = 46;
/// Attach object to player.
pub const RPC_ATTACH_OBJECT_TO_PLAYER: u8 = 75;
pub const RPC_SET_PLAYER_ATTACHED_OBJECT: u8 = 113;

/// Let player select an object by clicking.
pub const RPC_PLAYER_BEGIN_OBJECT_SELECT: u8 = 27;
pub const RPC_ON_PLAYER_SELECT_OBJECT: u8 = 27;
/// Let player edit/move an object manually.
pub const RPC_PLAYER_BEGIN_OBJECT_EDIT: u8 = 117;
pub const RPC_ON_PLAYER_EDIT_OBJECT: u8 = 117;
pub const RPC_PLAYER_CANCEL_OBJECT_EDIT: u8 = 28;
/// Edit attached object manually.
pub const RPC_PLAYER_BEGIN_ATTACHED_OBJECT_EDIT: u8 = 116;
pub const RPC_ON_PLAYER_EDIT_ATTACHED_OBJECT: u8 = 116;

/// Create pickup.
pub const RPC_PLAYER_CREATE_PICKUP: u8 = 95;
/// Destroy pickup.
pub const RPC_PLAYER_DESTROY_PICKUP: u8 = 63;
/// Event when player picks up pickup.
pub const RPC_ON_PLAYER_PICK_UP_PICKUP: u8 = 131;

/// Show text draw on screen.
pub const RPC_PLAYER_SHOW_TEXT_DRAW: u8 = 134;
/// Hide text draw.
pub const RPC_PLAYER_HIDE_TEXT_DRAW: u8 = 135;
/// Set text draw string.
pub const RPC_PLAYER_TEXT_DRAW_SET_STRING: u8 = 105;
/// Enable clicking on textdraws.
pub const RPC_PLAYER_BEGIN_TEXT_DRAW_SELECT: u8 = 83;
pub const RPC_ON_PLAYER_SELECT_TEXT_DRAW: u8 = 83;

/// Create 3D text label.
pub const RPC_PLAYER_SHOW_TEXT_LABEL: u8 = 36;
/// Destroy 3D text label.
pub const RPC_PLAYER_HIDE_TEXT_LABEL: u8 = 58;

/// Warp player into vehicle.
pub const RPC_PUT_PLAYER_IN_VEHICLE: u8 = 70;
/// Set vehicle health.
pub const RPC_SET_VEHICLE_HEALTH: u8 = 147;
/// Link vehicle to virtual interior.
pub const RPC_LINK_VEHICLE_TO_INTERIOR: u8 = 65;
/// Set vehicle Z rotation angle.
pub const RPC_SET_VEHICLE_Z_ANGLE: u8 = 160;
/// Eject player from vehicle.
pub const RPC_REMOVE_PLAYER_FROM_VEHICLE: u8 = 71;
/// Stream vehicle in.
pub const RPC_STREAM_IN_VEHICLE: u8 = 164;
/// Stream vehicle out.
pub const RPC_STREAM_OUT_VEHICLE: u8 = 165;
/// Event when player attempts to enter vehicle.
pub const RPC_ON_PLAYER_ENTER_VEHICLE: u8 = 26;
pub const RPC_ENTER_VEHICLE: u8 = 26;
/// Event when player exits vehicle.
pub const RPC_ON_PLAYER_EXIT_VEHICLE: u8 = 154;
pub const RPC_EXIT_VEHICLE: u8 = 154;
/// Set license plate.
pub const RPC_SET_VEHICLE_PLATE: u8 = 123;
/// Teleport vehicle.
pub const RPC_SET_VEHICLE_POSITION: u8 = 159;
/// Set vehicle body damages.
pub const RPC_SET_VEHICLE_DAMAGE_STATUS: u8 = 106;
/// Remove vehicle component (tuning).
pub const RPC_REMOVE_VEHICLE_COMPONENT: u8 = 57;
/// Event when vehicle is destroyed.
pub const RPC_VEHICLE_DEATH: u8 = 136;
/// Attach trailer to vehicle.
pub const RPC_ATTACH_TRAILER: u8 = 148;
/// Detach trailer.
pub const RPC_DETACH_TRAILER: u8 = 149;
/// Push/set vehicle velocity.
pub const RPC_SET_VEHICLE_VELOCITY: u8 = 91;
/// Set doors, engine, lights, bonnet, etc.
pub const RPC_SET_VEHICLE_PARAMS: u8 = 24;

/// Custom model download.
pub const RPC_MODEL_REQUEST: u8 = 179;
pub const RPC_MODEL_URL: u8 = 183;
pub const RPC_DOWNLOAD_COMPLETED: u8 = 185;
pub const RPC_FINISH_DOWNLOAD: u8 = 184;
pub const RPC_REQUEST_TXD: u8 = 182;
pub const RPC_REQUEST_DFF: u8 = 181;

/// Event when client sends RCON command.
pub const PACKET_PLAYER_RCON_COMMAND: u8 = 201;


// --- Synchronization Packet Identifiers (Player/Vehicle Sync) ---

/// Sync data for on-foot players.
pub const PACKET_PLAYER_FOOT_SYNC: u8 = 207;
/// Sync data for vehicle drivers.
pub const PACKET_PLAYER_VEHICLE_SYNC: u8 = 200;
/// Sync data for passengers.
pub const PACKET_PLAYER_PASSENGER_SYNC: u8 = 211;
/// Sync data for unoccupied vehicles.
pub const PACKET_PLAYER_UNOCCUPIED_SYNC: u8 = 209;
/// Sync data for trailers.
pub const PACKET_PLAYER_TRAILER_SYNC: u8 = 210;
/// Sync data for aiming.
pub const PACKET_PLAYER_AIM_SYNC: u8 = 203;
/// Sync data for bullet shots.
pub const PACKET_PLAYER_BULLET_SYNC: u8 = 206;
/// Sync data for stats update.
pub const PACKET_PLAYER_STATS_SYNC: u8 = 205;
/// Weapons update sync.
pub const PACKET_PLAYER_WEAPONS_UPDATE: u8 = 204;
/// Sync data for radar markers.
pub const PACKET_PLAYER_MARKERS_SYNC: u8 = 208;
/// Sync data for spectators.
pub const PACKET_PLAYER_SPECTATOR_SYNC: u8 = 212;
pub const PACKET_SCMEVENT: u8 = 96;
pub const PACKET_CLIENT_CHECK: u8 = 103;
pub const PACKET_PLAYER_CLOSE: u8 = 40;
pub const PACKET_SET_PLAYER_VIRTUAL_WORLD: u8 = 48;
pub const PACKET_SEND_GAME_TEXT: u8 = 73;
pub const PACKET_FORCE_PLAYER_CLASS_SELECTION: u8 = 74;
