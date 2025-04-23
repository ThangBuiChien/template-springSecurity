package com.laurentiuspilca.ssia.security;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.util.Base64;

public class GetKeyLocal {

    public static void main(String[] args) {
        // Generate a secure key
        byte[] keyBytes = Keys.secretKeyFor(SignatureAlgorithm.HS512).getEncoded();
        String secretKey = Base64.getEncoder().encodeToString(keyBytes);
        System.out.println(secretKey);
    }
}
