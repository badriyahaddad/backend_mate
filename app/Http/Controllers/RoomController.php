<?php

namespace App\Http\Controllers;

use App\Http\Requests\CreateRoomRequest;
use App\Http\Requests\AddUserToRoomRequest;
use App\Http\Requests\AssignCollaboratorRequest;
use App\Models\Room;
use App\Models\User;
use Illuminate\Support\Facades\Storage;
use Illuminate\Http\JsonResponse;

class RoomController extends Controller
{
    // Create a new room
    public function store(CreateRoomRequest $request): JsonResponse
    {
        $room = Room::create($request->validated());

        $room->users()->attach($request->admin_id);

        $this->storeRoomData($room);

        return response()->json(['message' => 'Room created successfully', 'room' => $room], 201);
    }

    // Add a user to the room
    public function addUser(AddUserToRoomRequest $request, $roomId): JsonResponse
    {
        $room = Room::findOrFail($roomId);
        $user = User::findOrFail($request->user_id);

        if ($room->users()->where('user_id', $user->id)->exists()) {
            return response()->json(['message' => 'User is already in the room'], 400);
        }

        $room->users()->attach($user->id);
        $room->increment('number_of_users');

        $this->storeUserData($user);

        return response()->json(['message' => 'User added successfully to the room'], 200);
    }

    // Assign a collaborator role
    public function assignCollaborator(AssignCollaboratorRequest $request, $roomId): JsonResponse
    {
        $room = Room::findOrFail($roomId);
        $user = User::findOrFail($request->user_id);

        if (!$room->users()->where('user_id', $user->id)->exists()) {
            return response()->json(['message' => 'User is not in the room'], 400);
        }

        $room->users()->updateExistingPivot($user->id, ['role' => 'collaborator']);

        return response()->json(['message' => 'Collaborator assigned successfully'], 200);
    }

    // Retrieve all rooms
    public function index(): JsonResponse
    {
        $rooms = Room::with('users')->get();

        return response()->json(['rooms' => $rooms], 200);
    }

    // Private methods for storage
    private function storeRoomData(Room $room): void
    {
        Storage::put('rooms/' . $room->id . '_data.json', $room->toJson());
    }

    private function storeUserData(User $user): void
    {
        Storage::put('users/' . $user->id . '_data.json', $user->toJson());
    }
}