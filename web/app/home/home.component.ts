import { Component, OnInit } from "@angular/core";
import { Router } from "@angular/router";
import { DimensionAuthService } from "../shared/services/dimension-auth.service";

@Component({
    selector: "my-home",
    templateUrl: "./home.component.html",
    styleUrls: ["./home.component.scss"],
})
export class HomeComponent implements OnInit {
    public hostname: string = window.location.origin;
    public showPromoPage = this.hostname === "https://dimension.t2bot.io";

    public integrationsConfig =
    `` +
    `"integrations_ui_url": "${this.hostname}/element",\n` +
    `"integrations_rest_url": "${this.hostname}/api/v1/scalar",\n` +
    `"integrations_widgets_urls": ["${this.hostname}/widgets"],\n` +
    `"integrations_jitsi_widget_url": "${this.hostname}/widgets/jitsi",\n`;

    constructor(private auth: DimensionAuthService, private router: Router) {
    // Do stuff
    }

    public ngOnInit(): void {
        if (!this.auth.isLoggedIn()) {
            this.router.navigate(["/login"]).catch(() => undefined);
        }
    }
}
