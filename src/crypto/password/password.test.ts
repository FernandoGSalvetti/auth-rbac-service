import { hashPassword, verifyPassword } from "../../crypto/password/password";
import { expect, test } from 'vitest';
import { EmptyPasswordError } from "../../errors/EmptyPassword";


const PASSWORD = 'secret-goals-19201'
const hashedPassword = async () => await hashPassword(PASSWORD);
const experiment = 'teste-123';

test('should return true for password verify', async () => {
    await expect(await verifyPassword(await hashedPassword(), PASSWORD)).toBe(true);
});

test('should return false for password verify', async () => {
    await expect(await verifyPassword(await hashedPassword(), experiment)).toBe(false);
});


test('should return false for blank password verify', async () => {
    await expect(await verifyPassword(await hashedPassword(), '   ')).toBe(false);
})

test('should throw error for blank password verify on hashPassword() method', async () => {
    await expect(hashPassword('   ')).rejects.toThrow(EmptyPasswordError)
})