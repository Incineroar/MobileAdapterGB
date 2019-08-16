<?php

function decodeExchange ($stream, $pkm = true) {
    $postdata = fopen($stream, "rb");
    $decData = array();
    $decData["email"] = fread($postdata, 0x18); // $00 DION e-mail address (null-terminated ASCII)
    fseek($postdata, 0x1E); // Jump to Trainer ID
    $decData["trainer_id"] = bin2hex(fread($postdata, 0x2)); // $1E Trainer ID
    $decData["secret_id"] = bin2hex(fread($postdata, 0x2)); // $20 Secret ID
    $decData["offer_gender"] = bin2hex(fread($postdata, 0x1)); // $22 Offered Pokémon’s gender
    $decData["offer_species"] = hexdec(bin2hex(fread($postdata, 0x1))); // $23 Offered Pokémon’s species
    $decData["req_gender"] = bin2hex(fread($postdata, 0x1)); // $24 Requested Pokémon’s gender
    $decData["req_species"] = hexdec(bin2hex(fread($postdata, 0x1))); // $25 Requested Pokémon’s species
    $decData["b64_pokemon"] = $pkm ? base64_encode(fread($postdata, 0x69)) : NULL; // Base64 of the Pokémon that needs to be sent back in email.
    // These bytes (except for b64_pokemon) are all that the web scripts need to deal with.
    return $decData;
}