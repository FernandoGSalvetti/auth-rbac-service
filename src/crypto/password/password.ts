import * as argon2 from "argon2";
import { EmptyPasswordError } from "../../errors/EmptyPassword";

//Argon2i is better on password hashing, because is slower and resistant againts trade-off attacks
const HASH_TYPE = argon2.argon2id;

export function verifyPasswordLength(plainPassword: string): boolean {
    return plainPassword.trim().length > 0;
}

export async function hashPassword(plainPassword: string): Promise<string> {
    if(!verifyPasswordLength(plainPassword)) throw new EmptyPasswordError();
    return argon2.hash(plainPassword, { type: HASH_TYPE });
}


export async function verifyPassword(hash: string, plainPassword: string): Promise<boolean> {
    if(!verifyPasswordLength(plainPassword) || !verifyPasswordLength(hash)) return false;
    return argon2.verify(hash, plainPassword);
}