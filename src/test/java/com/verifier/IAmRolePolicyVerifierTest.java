package com.verifier;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.*;

public class IAmRolePolicyVerifierTest {

    IAmRolePolicyVerifier iAmRolePolicyVerifier;

    @BeforeEach
    public void setUp() {
        iAmRolePolicyVerifier = new IAmRolePolicyVerifier();
    }

    @Test
    public void shouldReturnTrueWhenPolicyIsValid(){
        // given
        String validPolicy = """
                {
                    "PolicyName": "root",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "IamListAccess",
                                "Effect": "Allow",
                                "Action": [
                                    "iam:ListRoles",
                                    "iam:ListUsers"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                }  
                """.trim();
        //when && then
        assertTrue(iAmRolePolicyVerifier.verifyIAmRolePolicy(validPolicy));
    }

    @Test
    public void shouldReturnTrueWhenStatementHasOnlyResourceField(){
        // given
        String validPolicy = """
                {
                    "PolicyName": "root",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Resource": "*"
                            }
                        ]
                    }
                }  
                """.trim();
        //when && then
        assertTrue(iAmRolePolicyVerifier.verifyIAmRolePolicy(validPolicy));
    }

    @Test
    public void shouldReturnTrueWhenThereAreMoreValidStatements(){
        // given
        String validPolicy = """
                {
                    "PolicyName": "root",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "IamListAccess",
                                "Effect": "Allow",
                                "Action": [
                                    "iam:ListRoles",
                                    "iam:ListUsers"
                                ],
                                "Resource": "*"
                            },
                            {
                                "Sid": "IamListAccess2",
                                "Effect": "Allow",
                                "Action": [
                                    "iam:ListRoles2",
                                    "iam:ListUsers2"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                } 
                """.trim();
        //when && then
        assertTrue(iAmRolePolicyVerifier.verifyIAmRolePolicy(validPolicy));
    }

    @Test
    public void shouldReturnFalseWhenPolicyNameFieldIsAbsent(){
        // given
        String validPolicy = """
                {
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "IamListAccess",
                                "Effect": "Allow",
                                "Action": [
                                    "iam:ListRoles",
                                    "iam:ListUsers"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                }  
                """.trim();
        //when && then
        assertFalse(iAmRolePolicyVerifier.verifyIAmRolePolicy(validPolicy));
    }

    @Test
    public void shouldReturnFalseWhenPolicyDocumentFieldIsAbsent(){
        // given
        String validPolicy = """
               {
                    "PolicyName": "root"
               } 
                """.trim();
        //when && then
        assertFalse(iAmRolePolicyVerifier.verifyIAmRolePolicy(validPolicy));
    }

    @Test
    public void shouldReturnFalseWhenThereIsNotAllowedField(){
        // given
        String validPolicy = """
                {
                    "PolicyName": "root",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "IamListAccess",
                                "Effect": "Allow",
                                "Action": [
                                    "iam:ListRoles",
                                    "iam:ListUsers"
                                ],
                                "Resource": "*"
                            }
                        ]
                    },
                    "NotAllowedField": "value"
                }  
                """.trim();
        //when && then
        assertFalse(iAmRolePolicyVerifier.verifyIAmRolePolicy(validPolicy));
    }

    @Test
    public void shouldReturnFalseWhenThereIsNotAllowedFieldInStatement(){
        // given
        String validPolicy = """
                {
                    "PolicyName": "root",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "IamListAccess",
                                "Effect": "Allow",
                                "Action": [
                                    "iam:ListRoles",
                                    "iam:ListUsers"
                                ],
                                "Resource": "*",
                                "NotAllowedField": "value"
                            }
                        ]
                    }
                }  
                """.trim();
        //when && then
        assertFalse(iAmRolePolicyVerifier.verifyIAmRolePolicy(validPolicy));
    }

    @Test
    public void shouldReturnFalseWhenThereAreTwoStarsInResourceField(){
        // given
        String validPolicy = """
                {
                    "PolicyName": "root",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "IamListAccess",
                                "Effect": "Allow",
                                "Action": [
                                    "iam:ListRoles",
                                    "iam:ListUsers"
                                ],
                                "Resource": "**",
                            }
                        ]
                    }
                }  
                """.trim();
        //when && then
        assertFalse(iAmRolePolicyVerifier.verifyIAmRolePolicy(validPolicy));
    }

    @Test
    public void shouldReturnFalseWhenThereIsSomeStringInResource(){
        // given
        String validPolicy = """
                {
                    "PolicyName": "root",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "IamListAccess",
                                "Effect": "Allow",
                                "Action": [
                                    "iam:ListRoles",
                                    "iam:ListUsers"
                                ],
                                "Resource": "something",
                                "NotAllowedField": "value"
                            }
                        ]
                    }
                }  
                """.trim();
        //when && then
        assertFalse(iAmRolePolicyVerifier.verifyIAmRolePolicy(validPolicy));
    }

    @Test
    public void shouldReturnFalseWhenJsonIsNotValid(){
        //given
        String invalidJson= """
                {
                    "invalid": "json
                }
                """.trim();
        //when && then
        assertFalse(iAmRolePolicyVerifier.verifyIAmRolePolicy(invalidJson));
    }

    @Test
    public void shouldReturnFalseWhenJsonIsEmpty(){
        //given
        String invalidJson= """
                {
                    
                }
                """.trim();
        //when && then
        assertFalse(iAmRolePolicyVerifier.verifyIAmRolePolicy(invalidJson));
    }

    @Test
    public void shouldReturnFalseWhenThereIsEmptyString(){
        //given
        String invalidJson="";
        //when && then
        assertFalse(iAmRolePolicyVerifier.verifyIAmRolePolicy(invalidJson));
    }

}