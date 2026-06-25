import { Component, OnInit } from "@angular/core";
import { Router } from "@angular/router";
import { DimensionAuthService, AuthStatus } from "../shared/services/dimension-auth.service";
import { TranslateService } from "@ngx-translate/core";

@Component({
    selector: "my-login",
    templateUrl: "./login.component.html",
    styleUrls: ["./login.component.scss"],
})
export class LoginComponent implements OnInit {
    public username = "";
    public password = "";
    public email = "";
    public mode: "login" | "register" = "login";
    public error: string | null = null;
    public loading = false;

    public status: AuthStatus | null = null;
    public oidcLoginUrl: string | null = null;

    constructor(
        private auth: DimensionAuthService,
        private router: Router,
        private translate: TranslateService,
    ) {}

    public ngOnInit(): void {
        if (this.auth.isLoggedIn()) {
            this.router.navigate(["/"]).catch(() => undefined);
            return;
        }
        this.auth.getStatus().subscribe({
            next: (s) => {
                this.status = s;
                this.oidcLoginUrl = this.buildOidcUrl(s);
            },
            catch: () => {
                this.status = {
                    better_auth_enabled: false,
                    oidc_enabled: false,
                    oidc_issuer: null,
                    oidc_audience: null,
                    allow_public_registration: false,
                    has_admin: false,
                    bootstrap_admin_configured: false,
                };
            },
        });
    }

    public submit(): void {
        this.error = null;
        this.loading = true;
        const next = () => {
            this.loading = false;
            this.router.navigate(["/"]).catch(() => undefined);
        };
        const fail = (err: any) => {
            this.loading = false;
            this.error = (err && err.error && err.error.error) || "login failed";
        };
        if (this.mode === "login") {
            this.auth.login(this.username, this.password).subscribe({next, catch: fail});
        } else {
            this.auth.register(this.username, this.password, this.email || undefined).subscribe({
                next: () => this.auth.login(this.username, this.password).subscribe({next, catch: fail}),
                catch: fail,
            });
        }
    }

    public startOidc(): void {
        if (this.oidcLoginUrl) {
            window.location.href = this.oidcLoginUrl;
        }
    }

    public toggleMode(): void {
        this.mode = this.mode === "login" ? "register" : "login";
        this.error = null;
    }

    private buildOidcUrl(s: AuthStatus): string | null {
        if (!s.oidc_enabled || !s.oidc_issuer || !s.oidc_audience) return null;
        // Audience is only the introspection hint; the actual client_id
        // comes from the backend env so we don't leak it here. The
        // redirect_uri points to our own handler which forwards to the
        // backend.
        const clientId = "dimension-web";
        const redirectUri = window.location.origin + "/auth/oidc/redirect";
        return (
            s.oidc_issuer.replace(/\/$/, "") + "/authorize" +
            "?client_id=" + encodeURIComponent(clientId) +
            "&response_type=code" +
            "&scope=openid%20email%20profile" +
            "&redirect_uri=" + encodeURIComponent(redirectUri)
        );
    }
}
