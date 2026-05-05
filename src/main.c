/*
 * remoteTool - entry point.
 *
 * Stays deliberately tiny: lifecycle is owned by core/app.c so this
 * file never grows when subsystems are added.
 */

#include "core/app.h"

int main(int argc, char **argv)
{
    rt_app_t *app = rt_app_new();
    if (app == NULL) {
        return 1;
    }

    int status = rt_app_run(app, argc, argv);
    rt_app_free(app);
    return status;
}
