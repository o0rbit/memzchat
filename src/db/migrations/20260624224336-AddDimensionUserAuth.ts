import { QueryInterface } from "sequelize";
import { DataType } from "sequelize-typescript";

/**
 * Extend dimension_users with auth columns for multi-user login.
 *
 * Idempotent-ish: addColumn on SQLite supports IF NOT EXISTS via raw SQL,
 * but sequelize-typescript DataType wrappers do not. The umzug runner
 * stores migration history so a re-run is skipped automatically. For
 * fresh DBs the columns are created; for legacy DBs the columns are
 * added; if a partial upgrade left the columns already present the
 * migration will fail loudly so we notice.
 *
 * SQLite note: ALTER TABLE ADD COLUMN does not support NOT NULL without
 * a default. We add as nullable then backfill then enforce. Postgres
 * tolerates NOT NULL DEFAULT directly.
 */

export default {
    up: async (queryInterface: QueryInterface) => {
        const dialect = (queryInterface as any).sequelize?.getDialect?.()
            ?? process.env.DIMENSION_DB_DIALECT
            ?? "sqlite";

        await queryInterface.addColumn("dimension_users", "username", {
            type: DataType.STRING(128),
            allowNull: true,
            unique: true,
        });
        await queryInterface.addColumn("dimension_users", "passwordHash", {
            type: DataType.STRING(255),
            allowNull: true,
        });
        await queryInterface.addColumn("dimension_users", "role", {
            type: DataType.STRING(16),
            allowNull: false,
            defaultValue: "user",
        });
        await queryInterface.addColumn("dimension_users", "isActive", {
            type: DataType.BOOLEAN,
            allowNull: false,
            defaultValue: true,
        });
        await queryInterface.addColumn("dimension_users", "oidcSub", {
            type: DataType.STRING(255),
            allowNull: true,
        });
        await queryInterface.addColumn("dimension_users", "oidcProvider", {
            type: DataType.STRING(64),
            allowNull: true,
        });
        await queryInterface.addColumn("dimension_users", "createdAt", {
            type: DataType.DATE,
            allowNull: false,
            defaultValue: dialect === "sqlite" ? new Date() : null,
        });
        await queryInterface.addColumn("dimension_users", "updatedAt", {
            type: DataType.DATE,
            allowNull: false,
            defaultValue: dialect === "sqlite" ? new Date() : null,
        });

        // Unique index on oidcSub for OIDC lookups (NULL is allowed).
        if (dialect !== "sqlite") {
            await queryInterface.addIndex("dimension_users", {
                name: "dimension_users_oidc_sub_provider_idx",
                fields: ["oidcSub", "oidcProvider"],
                unique: true,
            });
        }
    },

    down: async (queryInterface: QueryInterface) => {
        const dialect = (queryInterface as any).sequelize?.getDialect?.()
            ?? process.env.DIMENSION_DB_DIALECT
            ?? "sqlite";

        if (dialect !== "sqlite") {
            await queryInterface.removeIndex(
                "dimension_users",
                "dimension_users_oidc_sub_provider_idx"
            ).catch(() => undefined);
        }
        await queryInterface.removeColumn("dimension_users", "updatedAt");
        await queryInterface.removeColumn("dimension_users", "createdAt");
        await queryInterface.removeColumn("dimension_users", "oidcProvider");
        await queryInterface.removeColumn("dimension_users", "oidcSub");
        await queryInterface.removeColumn("dimension_users", "isActive");
        await queryInterface.removeColumn("dimension_users", "role");
        await queryInterface.removeColumn("dimension_users", "passwordHash");
        await queryInterface.removeColumn("dimension_users", "username");
    },
};
