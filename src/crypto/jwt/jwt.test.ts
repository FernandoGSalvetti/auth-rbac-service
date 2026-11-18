import { expect, test } from "vitest";
import { getSigninInput, sign, toBase64Url, verifyJwt } from "./jwt";
import { JwtDTO } from "../../dtos/jwt";
import { randomUUID } from "node:crypto";
const SUB = randomUUID();
const baseJwtDTO: JwtDTO = {
    role: 'student',
    sub: SUB,
}

const secret = 'my-secret-123'


const signBaseJWT = (expersInSeconds: number = 60) => sign(baseJwtDTO, secret, expersInSeconds);


test('should return payload for a valid JWT', () => {
    const sign = signBaseJWT();
    const verify = verifyJwt(sign, secret);
    expect(verify).not.toBeNull();
})


test('should return null when JWT payload is tampered', () => {
    const sign = signBaseJWT();
    const [encodedHeader, _, encodedSignature] = sign.split('.');

    const modifiedPayload = toBase64Url(JSON.stringify({ role: 'teacher', sub: SUB }));
    const signinInput = getSigninInput(encodedHeader || '', modifiedPayload); 
    const verify = verifyJwt(`${signinInput}.${encodedSignature}`, secret)
    expect(verify).toBeNull();
})

test('should return null when JWT expiration time is down', () => {
    const sign = signBaseJWT(-1);
    const verify = verifyJwt(sign, secret);
    expect(verify).toBeNull();
})

test('should return null when secret is invalid', () => {
    const sign = signBaseJWT();
    const verify = verifyJwt(sign, 'new-secret');
    expect(verify).toBeNull();
})

test('should return the same knew object when JWT payload is valid', () => {
    const sign = signBaseJWT();
    const verify = verifyJwt(sign, secret);
    expect(verify).toMatchObject(baseJwtDTO);
})