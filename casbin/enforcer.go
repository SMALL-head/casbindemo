package casbin

import (
	"database/sql"
	sqladapter "github.com/Blank-Xu/sql-adapter"
	"github.com/casbin/casbin/v2"
	_ "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
)

func NewEnforcerWithDb(driverName string, dbSource string, model interface{}) *casbin.Enforcer {
	db, err := sql.Open(driverName, dbSource)
	if err != nil {
		logrus.Fatalf("[NewEnforcerWithDb] - error connecting to db, err = %v", err)
	}
	if err = db.Ping(); err != nil {
		logrus.Fatalf("[NewEnforcerWithDb]- ping db err: %v", err)
	}
	adapter, err := sqladapter.NewAdapter(db, driverName, "casbin")
	if err != nil {
		logrus.Fatalf("[NewEnforcerithDb] - new sql adpapter err = %v", err)
	}
	enforcer, err := casbin.NewEnforcer(model, adapter)
	if err != nil {
		logrus.Fatalf("[NewEnforcerWithDb] - create enforcer err: %v", err)
	}
	return enforcer
}
