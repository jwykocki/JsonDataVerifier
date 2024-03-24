package com.verifier;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import netscape.javascript.JSObject;

public class IAmRolePolicyVerifier {
    public boolean verifyIAmRolePolicy(String policy) {
        JsonNode object;
        try {
            object = new ObjectMapper().readTree(policy);
        }catch(JsonProcessingException e){
            return false;
        }
        return true;
    }

    public IAmRolePolicyVerifier() {
    }
}
