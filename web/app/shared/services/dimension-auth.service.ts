import { Injectable } from "@angular/core";
import { HttpClient } from "@angular/common/http";
import { BehaviorSubject, Observable, of } from "rxjs";
import { tap, catchError, map } from "rxjs/operators";
import { SessionStorage } from "./SessionStorage";

export interface DimensionAuthUser {
    userId: string;
    username: string;
    role: "user" | "admin";
}

export interface LoginResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    user: DimensionAuthUser;
    source: string;
}

export interface AuthStatus {
    better_auth_enabled: boolean;
    oidc_enabled: boolean;
    oidc_issuer: string | null;
    oidc_audience: string | null;
    allow_public_registration: boolean;
    has_admin: boolean;
    bootstrap_admin_configured: boolean;
}

@Injectable()
export class DimensionAuthService {
    private apiBase = "/api/v1/dimension/auth";
    private currentUser$ = new BehaviorSubject<DimensionAuthUser | null>(null);

    constructor(private http: HttpClient) {
        this.restoreSession();
    }

    private restoreSession(): void {
        const token = localStorage.getItem("dimension_auth_token");
        const userRaw = localStorage.getItem("dimension_auth_user");
        if (token && userRaw) {
            try {
                this.currentUser$.next(JSON.parse(userRaw));
            } catch {
                this.clearSession();
            }
        }
    }

    public getStatus(): Observable<AuthStatus> {
        return this.http.get<AuthStatus>(`${this.apiBase}/status`);
    }

    public getCurrentUser(): Observable<{authenticated: boolean; user?: DimensionAuthUser; source?: string}> {
        const token = localStorage.getItem("dimension_auth_token");
        if (!token) return of({authenticated: false});
        return this.http.get(`${this.apiBase}/me`, {headers: this.authHeaders()}).pipe(
            map((res: any) => ({authenticated: true, user: res.user, source: res.source})),
            catchError(() => {
                this.clearSession();
                return of({authenticated: false});
            })
        );
    }

    public login(username: string, password: string): Observable<LoginResponse> {
        return this.http.post<LoginResponse>(`${this.apiBase}/login`, {username, password}).pipe(
            tap((res) => this.storeSession(res)),
            catchError((err) => {
                this.clearSession();
                throw err;
            })
        );
    }

    public register(username: string, password: string, email?: string): Observable<any> {
        return this.http.post(`${this.apiBase}/register`, {username, password, email});
    }

    public logout(): void {
        this.clearSession();
    }

    public isLoggedIn(): boolean {
        return !!localStorage.getItem("dimension_auth_token");
    }

    public isAdmin(): boolean {
        const u = this.currentUser$.value;
        return !!u && u.role === "admin";
    }

    public getToken(): string | null {
        return localStorage.getItem("dimension_auth_token");
    }

    public getAuthHeaders(): {Authorization: string} {
        const t = this.getToken();
        return t ? {Authorization: `Bearer ${t}`} : {} as any;
    }

    /**
     * Redirect the browser to the OIDC provider login page.
     * The provider redirects back to /auth/oidc/redirect?code=...&state=...
     * which the OIDC redirect handler picks up.
     */
    public startOidcLogin(issuer: string, clientId: string, redirectUri: string, state?: string): void {
        const authUrl = `${issuer.replace(/\/$/, "")}/authorize`
            + `?client_id=${encodeURIComponent(clientId)}`
            + `&response_type=code`
            + `&scope=openid%20email%20profile`
            + `&redirect_uri=${encodeURIComponent(redirectUri)}`
            + (state ? `&state=${encodeURIComponent(state)}` : "");
        window.location.href = authUrl;
    }

    public handleOidcCallback(code: string, redirectUri: string): Observable<LoginResponse> {
        return this.http.post<LoginResponse>(`${this.apiBase}/oidc/callback`, {code, redirect_uri: redirectUri}).pipe(
            tap((res) => this.storeSession(res))
        );
    }

    private storeSession(res: LoginResponse): void {
        localStorage.setItem("dimension_auth_token", res.access_token);
        localStorage.setItem("dimension_auth_user", JSON.stringify(res.user));
        this.currentUser$.next(res.user);
    }

    private clearSession(): void {
        localStorage.removeItem("dimension_auth_token");
        localStorage.removeItem("dimension_auth_user");
        this.currentUser$.next(null);
    }
}
