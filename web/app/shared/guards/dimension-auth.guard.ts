import { Injectable } from "@angular/core";
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from "@angular/router";
import { DimensionAuthService } from "../services/dimension-auth.service";

/**
 * Route guard that requires a valid Dimension auth session.
 *
 * Applied to the /riot-app subtree (the integration manager). Without a
 * valid JWT the user is redirected to /login. The guard also checks the
 * backend /auth/me endpoint to ensure the token has not expired server-side.
 */
@Injectable()
export class DimensionAuthGuard implements CanActivate {
    constructor(private auth: DimensionAuthService, private router: Router) {}

    public async canActivate(_route: ActivatedRouteSnapshot, _state: RouterStateSnapshot): Promise<boolean> {
        if (!this.auth.isLoggedIn()) {
            this.router.navigate(["/login"]).catch(() => undefined);
            return false;
        }
        // Verify with backend (token might have expired server-side)
        return new Promise<boolean>((resolve) => {
            this.auth.getCurrentUser().subscribe({
                next: (res) => {
                    if (res.authenticated) {
                        resolve(true);
                    } else {
                        this.router.navigate(["/login"]).catch(() => undefined);
                        resolve(false);
                    }
                },
                error: () => {
                    this.router.navigate(["/login"]).catch(() => undefined);
                    resolve(false);
                },
            });
        });
    }
}
