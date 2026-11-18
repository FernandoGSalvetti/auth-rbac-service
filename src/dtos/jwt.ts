import { Role } from "../types/role";

export interface JwtDTO {
    sub: string;
    role: Role;
}

export interface JwtPayload extends JwtDTO {
    iat: number;
    exp: number;
} 