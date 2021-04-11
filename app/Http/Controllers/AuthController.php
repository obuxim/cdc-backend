<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    // Register
    public function register(Request $request){
        $fields = $request->validate([
            'email' => 'required|string|unique:users,email',
            'name' => 'required|string',
            'password' => 'required|confirmed|string'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => Hash::make($fields['password']),
        ]);

        $token = $user->createToken(config('app.key'))->plainTextToken;

        $response = new \stdClass();
        $response->user = $user;
        $response->token = $token;

        return response()->json($response);
    }

    // Login
    public function login(Request $request)
    {
        $fields = $request->validate([
            'email' => 'string|required',
            'password' => 'string|required',
        ]);

        $user = User::where('email', $fields['email'])->first();

        $response = new \stdClass();
        if(!$user || !Hash::check($fields['password'], $user->password)){
            $response->error = true;
            $response->message = 'Wrong credentials!';
            return response()->json($response, 401);
        }

        $response->error = false;
        $response->message = "Successfully logged in!";
        $response->data = [
            'user' => $user,
            'token' => $user->createToken(config('app.key'))->plainTextToken
        ];

        return response()->json($response, 200);
    }
}
