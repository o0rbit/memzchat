import { Column, Model, PrimaryKey, Table } from "sequelize-typescript";

/**
 * Extended auth row for the multi-user feature.
 *
 * The pre-existing dimension_users table only stored userId + isSelfBot as a
 * foreign-key anchor for widgets/upstreams. We extend that table via the
 * 20260624224336-AddDimensionUserAuth migration with these auth columns:
 *
 *   - username          login name, unique, optional (legacy matrix users)
 *   - password_hash     scrypt N format, NULL when OIDC-only
 *   - role              "user" or "admin"
 *   - is_active         soft-delete flag, default true
 *   - oidc_sub          OIDC subject claim, unique, optional
 *   - oidc_provider     e.g. "authentik", NULL for native users
 *   - created_at        timestamptz
 *   - updated_at        timestamptz
 *
 * Lookup order for login:
 *   1. username + password_hash (native better-auth flow)
 *   2. oidc_sub + oidc_provider (OIDC callback flow)
 *   3. legacy matrix userId (kept for backward compat with existing API)
 */

export type DimensionUserRole = "user" | "admin";

@Table({
    tableName: "dimension_users",
    underscored: false,
    timestamps: true,
    createdAt: "created_at",
    updatedAt: "updated_at",
})
export default class DimensionUser extends Model<DimensionUser> {
    @PrimaryKey
    @Column
    userId: string;

    @Column
    isSelfBot: boolean;

    @Column({allowNull: true})
    username: string | null;

    @Column({allowNull: true})
    passwordHash: string | null;

    @Column({allowNull: false, defaultValue: "user"})
    role: DimensionUserRole;

    @Column({allowNull: false, defaultValue: true})
    isActive: boolean;

    @Column({allowNull: true})
    oidcSub: string | null;

    @Column({allowNull: true})
    oidcProvider: string | null;

    @Column
    createdAt: Date;

    @Column
    updatedAt: Date;
}
