
#ifndef RUMBLE_LUA_H
#define RUMBLE_LUA_H
#  include <lua.h>
#  include <lualib.h>
#  include <lauxlib.h>

int  rumble_lua_callback(lua_State *state, void *hook, void *session);
int         Foo_register(lua_State *L);
#endif /* RUMBLE_LUA_H */
