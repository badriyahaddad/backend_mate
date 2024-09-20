<?php

namespace App\Http\Controllers;
use App\Models\TestModel;

use Illuminate\Http\Request;
use App\Http\Requests\TestRequest;
use Faker\Provider\ar_EG\Person;

class TestController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function firstAction(TestRequest $request)
    {
        $data = $request->validated();

        // Store the data in the database
        $name = TestModel::create($data);

        return response()->json([
            'message' => 'Name and age stored successfully!',
            'stored_data' => $name
        ]);
    }
//-------------------------------------------------------
    public function showNames()
    {
        // Retrieve all names and ages from the database
        $names = TestModel::all()->map(function ($person) {
            // Check if the person is under 18
            if ($person->age < 18) {
                $person->age = $person->age . ' (Underage)';
            }
            if ($person->name =='bardic hadar'){
                $person->name=$person->name . ' (this is the admin)';
            }
            return $person;
        });

        // Return the modified data as JSON
        return response()->json($names);
    }
// delete-------------------------------------------------------
    public function deleteName($id){
    $name = TestModel::findOrFail($id);
    $name->delete();

    return response()->json(['message' => 'Name deleted successfully'], 200);
}
//update-------------------------------------------------------
public function updateName(TestRequest $request, $id)
{
    $name = TestModel::findOrFail($id);
    $name->update($request->validated()); // Using validated data directly

    return response()->json(['message' => 'Name updated successfully'], 200);
}
//searching-------------------------------------------------------
public function searchNames(Request $request)
{
    $searchTerm = $request->query('term');
    $names = TestModel::where('name', 'LIKE', '%' . $searchTerm . '%')->get();
    return response()->json($names);
}
}