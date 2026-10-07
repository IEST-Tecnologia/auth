package keycloak

import (
	"time"
)

type cachedGroup struct {
	group     Group
	expiresAt time.Time
}

type cachedMember struct {
	member    Member
	expiresAt time.Time
}

func (c *AdminClient) cachedGroup(groupID string) (Group, bool) {
	c.groupCacheMu.RLock()
	defer c.groupCacheMu.RUnlock()

	entry, ok := c.groupCache[groupID]
	if !ok || time.Now().After(entry.expiresAt) {
		return Group{}, false
	}
	return entry.group, true
}

func (c *AdminClient) cacheGroup(groupID string, group Group) {
	c.groupCacheMu.Lock()
	defer c.groupCacheMu.Unlock()
	c.groupCache[groupID] = cachedGroup{group: group, expiresAt: time.Now().Add(c.groupCacheTTL)}
}

func (c *AdminClient) cachedUserGroup(userID string) (Group, bool) {
	c.groupCacheMu.RLock()
	defer c.groupCacheMu.RUnlock()

	entry, ok := c.userGroupCache[userID]
	if !ok || time.Now().After(entry.expiresAt) {
		return Group{}, false
	}
	return entry.group, true
}

func (c *AdminClient) cacheUserGroup(userID string, group Group) {
	c.groupCacheMu.Lock()
	defer c.groupCacheMu.Unlock()
	c.userGroupCache[userID] = cachedGroup{group: group, expiresAt: time.Now().Add(c.groupCacheTTL)}
}

func (c *AdminClient) cachedUser(userID string) (Member, bool) {
	c.userCacheMu.RLock()
	defer c.userCacheMu.RUnlock()

	entry, ok := c.userCache[userID]
	if !ok || time.Now().After(entry.expiresAt) {
		return Member{}, false
	}
	return entry.member, true
}

func (c *AdminClient) cacheUser(userID string, member Member) {
	c.userCacheMu.Lock()
	defer c.userCacheMu.Unlock()
	c.userCache[userID] = cachedMember{member: member, expiresAt: time.Now().Add(c.groupCacheTTL)}
}
