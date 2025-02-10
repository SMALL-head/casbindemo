package casbin

import (
	"github.com/casbin/casbin/v2/model"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"slices"
	"testing"
)

func TestPolicy(t *testing.T) {
	// 创建一个内存数据库
	enforcer := NewEnforcerWithDb("sqlite3", ":memory:", "../model.conf")

	testGroup := []struct {
		name string
	}{
		{
			name: "addPolicy",
		},
	}
	for _, tt := range testGroup {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := enforcer.AddPolicy("alice", "data1", "read")
			require.NoError(t, err)
			require.True(t, policy)
			enforce, err := enforcer.Enforce("alice", "data1", "read")
			require.NoError(t, err)
			require.True(t, enforce)
		})
	}
}

func TestRBACWithPattern(t *testing.T) {
	m, err := model.NewModelFromString(`
[request_definition]
r = username, url, method

[policy_definition]
p = sub, url, method

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.username, p.sub) && r.url == p.url && r.method == p.method || r.username == "admin"
`)
	require.NoError(t, err)
	enforcer := NewEnforcerWithDb("sqlite3", ":memory:", m)
	_, _ = enforcer.AddPolicies([][]string{
		{"data1_admin", "/data1", "POST"},
		{"data2_admin", "/data2", "POST"},
		{"bob", "/data1", "POST"},
	})

	_, _ = enforcer.AddGroupingPolicies([][]string{
		{"alice", "data1_admin"},
		{"bob", "data2_admin"},
	})

	// admin 可以访问所有资源
	r, _ := enforcer.Enforce("admin", "/data1", "POST")
	require.Equal(t, true, r)

	// alice 作为data1_admin可以访问 /data1
	r, _ = enforcer.Enforce("alice", "/data1", "POST")
	require.Equal(t, true, r)

	// bob 通过policy可以访问 /data1
	r, _ = enforcer.Enforce("bob", "/data1", "POST")
	require.Equal(t, true, r)
}

func TestABACPattern(t *testing.T) {
	type checkParam struct {
		checkFunc string
	}
	type checkFunc func(param *checkParam) (bool, error)

	m, _ := model.NewModelFromString(`
[request_definition]
r = username, url, method, para 

[policy_definition]
p = sub, url, method, funcName

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.username, p.sub) && r.url == p.url && r.method == p.method && verify(p.funcName, r.para) || r.username == "admin"
`)

	enforcer := NewEnforcerWithDb("sqlite3", ":memory:", m)
	funcMap := map[string]checkFunc{
		"fn1": func(param *checkParam) (bool, error) {
			return true, nil
		},
	}
	enforcer.AddFunction("verify", func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			logrus.Errorf("len of args isn't 2")
			return false, nil
		}
		fnName, ok := args[0].(string)

		if !ok {
			logrus.Errorf("args[0] err")
			return false, nil
		}
		c, exists := funcMap[fnName]
		if !exists {
			return false, nil
		}
		param, ok := args[1].(*checkParam)
		if !ok {
			logrus.Errorf("args[1] err")
			return false, nil
		}

		res, err := c(param)
		if err != nil {
			return false, err
		}
		return res, nil
	})

	_, _ = enforcer.AddPolicies([][]string{
		{"user", "/data1", "POST", "check1"},
		{"user", "/data2", "POST", "fn1"},
		{"global_read", "/data1", "POST", "pass"},
	})
	_, _ = enforcer.AddGroupingPolicies([][]string{
		{"bob", "root"},
	})
	// username是否是role ，这个有小点绕啊，而且还是闭包
	roleMapping := func(username string, role string) bool {
		roles, err := enforcer.GetRolesForUser(username)
		if err != nil {
			return false
		}
		if slices.Index(roles, username) >= 0 {
			return true
		} else {
			return role == "user" // 所有用户都是普通用户
		}
	}

	enforcer.AddNamedMatchingFunc("g", "role_mapping", roleMapping)

	var para checkParam
	r, err := enforcer.Enforce("alice", "/data1", "POST", &para)

	if err != nil {
		logrus.Errorf("err: %v", err)
	}
	roles, _ := enforcer.GetRolesForUser("alice")
	logrus.Infof("roles for alice: %v", roles)

	require.Equal(t, false, r)
	r, err = enforcer.Enforce("alice", "/data2", "POST", &para)
	if err != nil {
		logrus.Errorf("err: %v", err)
	}
	require.Equal(t, true, r)

}
