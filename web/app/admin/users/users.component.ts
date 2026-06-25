import { Component, OnInit } from "@angular/core";
import { AdminUsersApiService, AdminUser } from "../../shared/services/admin/admin-users-api.service";
import { NgbModal } from "@ng-bootstrap/ng-bootstrap";
import { TranslateService } from "@ngx-translate/core";

@Component({
    templateUrl: "./admin-users.html",
    styleUrls: ["./admin-users.scss"],
})
export class AdminUsersComponent implements OnInit {
    public users: AdminUser[] = [];
    public loading = true;
    public error: string | null = null;
    public creating = false;
    public editing: AdminUser | null = null;
    public newUser = {username: "", password: "", role: "user" as "user" | "admin", email: ""};

    constructor(
        private usersApi: AdminUsersApiService,
        private modal: NgbModal,
        private translate: TranslateService,
    ) {}

    public ngOnInit(): void {
        this.refresh();
    }

    public async refresh(): Promise<void> {
        this.loading = true;
        this.error = null;
        try {
            this.users = await this.usersApi.listUsers();
        } catch (e) {
            this.error = "Failed to load users. Are you an admin?";
        } finally {
            this.loading = false;
        }
    }

    public async createUser(): Promise<void> {
        if (!this.newUser.username || this.newUser.username.length < 3) return;
        if (!this.newUser.password || this.newUser.password.length < 8) return;
        try {
            await this.usersApi.createUser({
                username: this.newUser.username,
                password: this.newUser.password,
                role: this.newUser.role,
                email: this.newUser.email || undefined,
            });
            this.newUser = {username: "", password: "", role: "user", email: ""};
            this.creating = false;
            await this.refresh();
        } catch (e: any) {
            this.error = (e.error && e.error.error) || "Create failed";
        }
    }

    public async toggleActive(user: AdminUser): Promise<void> {
        try {
            await this.usersApi.updateUser(user.userId, {isActive: !user.isActive});
            await this.refresh();
        } catch {
            this.error = "Update failed";
        }
    }

    public async changeRole(user: AdminUser, role: "user" | "admin"): Promise<void> {
        try {
            await this.usersApi.updateUser(user.userId, {role});
            await this.refresh();
        } catch {
            this.error = "Role change failed";
        }
    }

    public async resetPassword(user: AdminUser): Promise<void> {
        const pw = prompt("New password for " + user.username + " (min 8 chars):");
        if (!pw || pw.length < 8) return;
        try {
            await this.usersApi.updateUser(user.userId, {password: pw});
            alert("Password updated");
        } catch {
            this.error = "Password reset failed";
        }
    }

    public async deleteUser(user: AdminUser): Promise<void> {
        if (!confirm("Delete user " + user.username + " (" + user.userId + ")? This cannot be undone.")) return;
        try {
            await this.usersApi.deleteUser(user.userId);
            await this.refresh();
        } catch {
            this.error = "Delete failed";
        }
    }

    public provideOidc(user: AdminUser): string {
        if (user.oidcSub && user.oidcProvider) {
            return user.oidcSub.slice(0, 12) + " @ " + user.oidcProvider;
        }
        return "native only";
    }
}
