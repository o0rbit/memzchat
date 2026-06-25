import { Component, OnInit } from "@angular/core";
import { ActivatedRoute, Router } from "@angular/router";
import { DimensionAuthService } from "../shared/services/dimension-auth.service";

/**
 * Handles the OIDC redirect from Authentik. The provider appends
 * ?code=...&state=... to this route. We forward the code to the backend
 * which exchanges it for a JWT and then redirect to the home page.
 */
@Component({
    selector: "my-oidc-redirect",
    template: "<p>Completing login...</p>",
})
export class OidcRedirectComponent implements OnInit {
    constructor(
        private route: ActivatedRoute,
        private auth: DimensionAuthService,
        private router: Router,
    ) {}

    public ngOnInit(): void {
        const code = this.route.snapshot.queryParamMap.get("code");
        const redirectUri = window.location.origin + "/auth/oidc/redirect";
        if (!code) {
            this.router.navigate(["/login"]).catch(() => undefined);
            return;
        }
        this.auth.handleOidcCallback(code, redirectUri).subscribe({
            next: () => this.router.navigate(["/"]).catch(() => undefined),
            error: () => this.router.navigate(["/login"]).catch(() => undefined),
        });
    }
}
