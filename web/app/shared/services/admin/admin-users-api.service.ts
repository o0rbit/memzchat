import { Injectable } from "@angular/core";
import { HttpClient } from "@angular/common/http";
import { DimensionAuthService } from "../dimension-auth.service";

export interface AdminUser {
    userId: string;
    username: string;
    email: string | null;
    role: "user" | "admin";
    isActive: boolean;
    oidcSub: string | null;
    oidcProvider: string | null;
    createdAt: string;
}

export interface CreateUserRequest {
    username: string;
    password: string;
    role?: "user" | "admin";
    email?: string;
}

export interface UpdateUserRequest {
    role?: "user" | "admin";
    isActive?: boolean;
    password?: string;
}

@Injectable()
export class AdminUsersApiService {
    private apiBase = "/api/v1/dimension/auth/admin";

    constructor(private http: HttpClient, private auth: DimensionAuthService) {}

    public listUsers(): Promise<AdminUser[]> {
        return this.http.get<AdminUser[]>(`${this.apiBase}/users`, {headers: this.auth.getAuthHeaders()}).toPromise();
    }

    public createUser(req: CreateUserRequest): Promise<{userId: string; username: string; role: string; created: boolean}> {
        return this.http.post<{userId: string; username: string; role: string; created: boolean}>(`${this.apiBase}/users`, req, {headers: this.auth.getAuthHeaders()}).toPromise();
    }

    public updateUser(userId: string, req: UpdateUserRequest): Promise<{updated: boolean}> {
        return this.http.patch<{updated: boolean}>(`${this.apiBase}/users/${encodeURIComponent(userId)}`, req, {headers: this.auth.getAuthHeaders()}).toPromise();
    }

    public deleteUser(userId: string): Promise<{deleted: boolean}> {
        return this.http.delete<{deleted: boolean}>(`${this.apiBase}/users/${encodeURIComponent(userId)}`, {headers: this.auth.getAuthHeaders()}).toPromise();
    }
}
