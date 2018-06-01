#define _POSIX_C_SOURCE 200809
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h> 
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <seccomp.h>
#include <time.h>

#include "shops.h"

#define UNUSED(x) (void)(x)

static sqlite3 *db;
static char *sql;
static User *global_user;
static Shop *global_shop;
struct timespec db_sleep, rem;

void exitFunc(int val) {
	sqlite3_close(db);
	exit(val);
}


void dieFunc(int sig) {
	if (sig != SIGTERM) {
		return;
	}
	exitFunc(EXIT_FAILURE);
}

void clearFunc(int sig) {
	if (sig != SIGUSR1) {
		return;
	}
	if (global_user != NULL) {
		free(global_user->pwd);
		memset(&global_shop, 0, sizeof(global_shop));
		free(global_user);
	}
	if (global_shop != NULL) {
		free(global_shop->name);
		free(global_shop->pwd);
		memset(&global_shop, 0, sizeof(global_shop));
		free(global_shop);
	}
	// VULN1: Don't clear reference to global_shop
}

void setupSeccomp(void) {
	scmp_filter_ctx filter;

	if ((filter = seccomp_init(SCMP_ACT_KILL)) == NULL) {
	//if ((filter = seccomp_init(SCMP_ACT_ALLOW)) == NULL) {
		exitFunc(EXIT_FAILURE);
	}
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(time), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(signal), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(sigaction), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(sigprocmask), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(fdatasync), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(fchown), 0);
	if (seccomp_load(filter) < 0){
		exitFunc(EXIT_FAILURE);
	}
	seccomp_release(filter);
}


size_t checkWrite (void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t ret;

	if ((ret = fwrite(ptr, size, nmemb, stream)) < nmemb) {
		perror("fwrite");
		exitFunc(EXIT_FAILURE);
	}
	fflush(stream);
	return ret;
}

size_t checkRead (void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t ret;
	StatusResp resp;

	if ((ret = fread(ptr, size, nmemb, stream)) < nmemb) {
		if (ferror(stream)) {
			perror("fread");
		}
		resp.status = -1;
		checkWrite(&resp, sizeof(resp), 1, stdout);
		exitFunc(EXIT_FAILURE);
	}
	return ret;
}


uint64_t llrand() {
	int i;
	uint64_t r = 0;
	for (i = 0; i < 4; ++i) {
		r = (r << 15) | (rand() & 0x7ff);
	}
	return r & 0xffffffffffffffffULL;
}


void createDB (void) {
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data/shops.db", &db);

	if( rc ) {
		exitFunc(EXIT_FAILURE);
	}
   /* Create SQL statement */
	sql = "CREATE TABLE IF NOT EXISTS USERS("	\
		"ID INT PRIMARY KEY	 NOT NULL," \
		"COINS			 INT64	 NOT NULL," \
		"PWD		     TEXT );";

	/* Execute SQL statement */
	//rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
   
	if( rc != SQLITE_OK ){
		sqlite3_free(zErrMsg);
	}



   /* Create SQL statement */
	sql = "CREATE TABLE IF NOT EXISTS SHOPS("	\
		"ID INT PRIMARY KEY	 NOT NULL," \
		"NAME			 TEXT	 NOT NULL," \
		"PWD		     TEXT," \
		"OWNER			 INT64	 NOT NULL," \
		"FOREIGN KEY(OWNER) REFERENCES USERS(ID) );";

	/* Execute SQL statement */
	//rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
   
	if( rc != SQLITE_OK ){
		sqlite3_free(zErrMsg);
	}

   /* Create SQL statement */
	sql = "CREATE TABLE IF NOT EXISTS ITEMS("	\
		"ID INT PRIMARY KEY	 NOT NULL," \
		"NAME			 TEXT	 NOT NULL," \
		"PRICE			 INT64	 NOT NULL," \
		"AMOUNT			 INT64	 NOT NULL," \
		"SHOP			 INT64	 NOT NULL," \
		"FOREIGN KEY(SHOP) REFERENCES SHOPS(ID) );";

	/* Execute SQL statement */
	//rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
   
	if( rc != SQLITE_OK ){
		sqlite3_free(zErrMsg);
	}
}


int DBlistShops (void) {
	int rc;
	sqlite3_stmt *stmt;  
	ListResp *resp;
	ssize_t resp_size;
	ListResp final_resp;
	const char *name;

	/* Create SQL statement */
	sql = "SELECT ID, NAME from SHOPS";
	sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);                              /* 2 */

	/* Execute SQL statement */

	//rc = sqlite3_exec(db, sql, list_callback, NULL, &zErrMsg);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		name =  (char *) sqlite3_column_text(stmt, 1);
		resp_size = sizeof(ListResp) + strlen(name) + 1;

		if ((resp = calloc(1, resp_size)) == NULL) {
			perror("calloc");
			exitFunc(EXIT_FAILURE);
		}
		resp->id = sqlite3_column_int64(stmt, 0);
		resp->name_len = strlen(name);
		memcpy(resp->name, name, strlen(name));

		checkWrite(resp, resp_size, 1, stdout);
		free(resp);
	}
	sqlite3_finalize(stmt);
	final_resp.id = -1;
	checkWrite(&final_resp, 1, sizeof(int64_t), stdout);
	return EXIT_SUCCESS;
}

int DBlistItems (uint64_t shop) {
	int rc;
	sqlite3_stmt *stmt;  
	ListResp *resp;
	ssize_t resp_size;
	ListResp final_resp;
	const char *name;

	if (shop == 0) {
	/* Create SQL statement */
		sql = "SELECT ID, NAME from ITEMS";
		sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
	} else {
		sql = "SELECT ID, NAME from ITEMS WHERE SHOP = ?1";
		sqlite3_prepare_v2(db, sql, strlen(sql), &stmt, NULL);
		sqlite3_bind_int64(stmt, 1, shop);
	}

	/* Execute SQL statement */
	//rc = sqlite3_exec(db, sql, list_callback, NULL, &zErrMsg);

	while ( (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		name =  (char *) sqlite3_column_text(stmt, 1);
		resp_size = sizeof(ListResp) + strlen(name) + 1;

		if ((resp = calloc(1, resp_size)) == NULL) {
			perror("calloc");
			exitFunc(EXIT_FAILURE);
		}
		resp->id = sqlite3_column_int64(stmt, 0);
		resp->name_len = strlen(name);
		memcpy(resp->name, name, strlen(name));

		checkWrite(resp, resp_size, 1, stdout);
		free(resp);
	}
	sqlite3_finalize(stmt);
	final_resp.id = -1;
	checkWrite(&final_resp, sizeof(ListResp), 1, stdout);
	return EXIT_SUCCESS;
}

User *DBgetUser (uint64_t id, char *pwd) {
	char *zErrMsg = 0;
	int rc;
	sqlite3_stmt *stmt;  
	User *user;


	if ((user = calloc(1, sizeof(User))) == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}


	/* Create SQL statement */
	sqlite3_prepare_v2(db, "SELECT ID, COINS, PWD FROM USERS WHERE ID = ?1 AND PWD like ?2;", -1,
        &stmt, NULL);


	sqlite3_bind_int64(stmt, 1, id);
	sqlite3_bind_text(stmt, 2, pwd, -1, SQLITE_STATIC);

	/* Execute SQL statement */
	if ( (rc = sqlite3_step(stmt)) != SQLITE_ROW) {
		sqlite3_free(zErrMsg);
		exit(EXIT_FAILURE);
	}
	user->id = sqlite3_column_int64(stmt, 0);
	user->pwd = (char *) sqlite3_column_text(stmt, 2);
	user->coins = sqlite3_column_int64(stmt, 1);
	return user;
}

Shop *DBgetShop (uint64_t id, char *pwd) {
	char *zErrMsg = 0;
	int rc;
	sqlite3_stmt *stmt;  
	Shop *shop;
	User *user;


	if ((shop = calloc(1, sizeof(Shop))) == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}


	/* Create SQL statement */
	sqlite3_prepare_v2(db, "SELECT ID, NAME, PWD, OWNER FROM SHOPS WHERE ID = ?1 AND PWD like ?2;", -1,
        &stmt, NULL);


	sqlite3_bind_int64(stmt, 1, id);
	sqlite3_bind_text(stmt, 2, pwd, -1, SQLITE_STATIC);

	/* Execute SQL statement */
	if ( (rc = sqlite3_step(stmt)) != SQLITE_ROW) {
		sqlite3_free(zErrMsg);
		exit(EXIT_FAILURE);
	}
	shop->id = sqlite3_column_int64(stmt, 0);
	shop->name = (char *) sqlite3_column_text(stmt, 1);
	shop->pwd = (char *) sqlite3_column_text(stmt, 2);

	if ((user = calloc(1, sizeof(User))) == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}
	shop->owner = user;
	shop->owner->id = sqlite3_column_int64(stmt, 3);
	return shop;
}

Item *DBgetItem (uint64_t id) {
	int rc;
	sqlite3_stmt *stmt;  
	Item *item;
	Shop *shop;


	if ((item = calloc(1, sizeof(Item))) == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}


	/* Create SQL statement */
	sqlite3_prepare_v2(db, "SELECT ID, PRICE, AMOUNT, NAME, SHOP FROM ITEMS WHERE ID = ?1 ;", -1,
        &stmt, NULL);


	sqlite3_bind_int64(stmt, 1, id);

	if ( (rc = sqlite3_step(stmt)) != SQLITE_ROW) {
	/* Execute SQL statement */
		exit(EXIT_FAILURE);
	}
	item->id = sqlite3_column_int64(stmt, 0);
	item->price = sqlite3_column_int64(stmt, 1);
	item->amount = sqlite3_column_int64(stmt, 2);
	item->name = (char *) sqlite3_column_text(stmt, 3);

	if ((shop = calloc(1, sizeof(Shop))) == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}
	item->shop = shop;
	item->shop->id = sqlite3_column_int64(stmt, 4);
	return item;
}


int DBaddUser (User *user) {
	int rc;
	sqlite3_stmt *stmt;  


	/* Create SQL statement */
	sqlite3_prepare_v2(db, "INSERT INTO USERS (ID, COINS, PWD) values (?1, ?2, ?3);", -1, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, user->id);
	sqlite3_bind_int64(stmt, 2, user->coins);
	sqlite3_bind_text(stmt, 3, user->pwd , -1, SQLITE_STATIC);

	/* Execute SQL statement */
	do {
		rc = sqlite3_step(stmt); 
		nanosleep(&db_sleep , &rem);
	} while (rc == SQLITE_BUSY);

	if (rc != SQLITE_DONE) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int DBaddShop (Shop *shop) {
	int rc;
	sqlite3_stmt *stmt;  

	/* Create SQL statement */
	sqlite3_prepare_v2(db, "INSERT INTO SHOPS (ID, NAME, PWD, OWNER) values (?1, ?2, ?3, ?4);", -1, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, shop->id);
	sqlite3_bind_text(stmt, 2, shop->name , -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, shop->pwd , -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 4, shop->owner->id);

	/* Execute SQL statement */
	do {
		rc = sqlite3_step(stmt); 
		nanosleep(&db_sleep , &rem);
	} while (rc == SQLITE_BUSY);

	if (rc != SQLITE_DONE) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int DBaddItem (Item *item) {
	int rc;
	sqlite3_stmt *stmt;  

	/* Create SQL statement */
	sqlite3_prepare_v2(db, "INSERT INTO ITEMS (ID, NAME, PRICE, AMOUNT, SHOP) values (?1, ?2, ?3, ?4, ?5);", -1, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, item->id);
	sqlite3_bind_text(stmt, 2, item->name , -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, item->price);
	sqlite3_bind_int64(stmt, 4, item->amount);
	sqlite3_bind_int64(stmt, 5, item->shop->id);

	/* Execute SQL statement */
	do {
		rc = sqlite3_step(stmt); 
		nanosleep(&db_sleep , &rem);
	} while (rc == SQLITE_BUSY);
	if (rc != SQLITE_DONE) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

void regUser(void) {
	StatusResp resp;
	User user;
	uint64_t pwd_len;

	checkRead(&pwd_len, sizeof(pwd_len), 1, stdin);
	

	if ((user.pwd = calloc(1, pwd_len)) == NULL) {
		perror("calloc");
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		exitFunc(EXIT_FAILURE);
	} else {
		resp.status = 0;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	}

	checkRead(user.pwd, pwd_len, 1, stdin);

	user.id = llrand();
	user.coins = 142;


	if (DBaddUser(&user) == EXIT_SUCCESS) {
		resp.status = user.id;
	} else {
		resp.status = -1;
	}

	checkWrite(&resp, sizeof(StatusResp), 1, stdout);

	free(user.pwd);
}

void loginUser(void) {
	ShopResp resp;
	User reqUser;
	User *dbUser;
	uint64_t pwd_len;

	if (global_user != NULL) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	} else {
		resp.status = 0;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	}

	checkRead(&reqUser.id, sizeof(reqUser.id), 1, stdin);

	checkRead(&pwd_len, sizeof(pwd_len), 1, stdin);
	
	if ((reqUser.pwd = calloc(1, pwd_len)) == NULL) {
		perror("calloc");
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		exitFunc(EXIT_FAILURE);
	} else {
		resp.status = 0;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	}

	checkRead(reqUser.pwd, pwd_len, 1, stdin);


	dbUser = DBgetUser(reqUser.id, reqUser.pwd);
	if (dbUser == NULL) {
		resp.status = -1;
	} else {
		global_user = dbUser;
		resp.status = 0;
	}

	checkWrite(&resp, sizeof(StatusResp), 1, stdout);

	free(reqUser.pwd);
}

void listShops(void) {
	DBlistShops();
	/* Maybe do smth in case of error */
}

void enterShop(void) {
	// TODO
	ShopResp resp;
	Shop reqShop;
	Shop *dbShop;
	uint64_t pwd_len;


	if (global_shop != NULL) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	} else {
		resp.status = 0;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	}

	checkRead(&reqShop.id, sizeof(reqShop.id), 1, stdin);

	checkRead(&pwd_len, sizeof(pwd_len), 1, stdin);
	
	if ((reqShop.pwd = calloc(1, pwd_len)) == NULL) {
		perror("calloc");
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		exitFunc(EXIT_FAILURE);
	} else {
		resp.status = 0;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	}

	checkRead(reqShop.pwd, pwd_len, 1, stdin);


	dbShop = DBgetShop(reqShop.id, reqShop.pwd);
	if (dbShop == NULL) {
		resp.status = -1;
	} else {
		global_shop = dbShop;
		resp.status = 0;
	}

	checkWrite(&resp, sizeof(StatusResp), 1, stdout);

	free(reqShop.pwd);

	return;
}

void createShop(void) {
	StatusResp resp;
	ShopCreateReq req;
	Shop *shop;
	char *name, *pwd;

	if (global_user == NULL) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		return;
	} else {
		resp.status = 0;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	}

	/*
	 * struct ShopCreateReq {
	 * 	size_t name_len;
	 * 	size_t pwd_len;
	 * 	char payload[];
	 * };
	 */

	checkRead(&req, sizeof(ShopCreateReq), 1, stdin);

	if ((name = calloc(1, req.name_len)) == NULL) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		perror("calloc");
		exitFunc(EXIT_FAILURE);
	}

	if ((pwd = calloc(1, req.pwd_len)) == NULL) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		perror("calloc");
		exitFunc(EXIT_FAILURE);
	}

	if ((shop = calloc(1, sizeof(Shop))) == NULL) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		perror("calloc");
		exitFunc(EXIT_FAILURE);
	}


	resp.status = 0;
	checkWrite(&resp, sizeof(StatusResp), 1, stdout);

	shop->id = llrand();
	shop->name = name;
	shop->pwd = pwd;
	shop->owner = global_user;

	checkRead(name, req.name_len, 1, stdin);
	// VULN2 just a copy-paste bug in here
	checkRead(pwd, req.name_len, 1, stdin);

	DBaddShop(shop);

	global_shop = shop;

	resp.status = shop->id;
	checkWrite(&resp, sizeof(StatusResp), 1, stdout);

	free(name);
	free(pwd);
}

void listItems(void) {
	StatusResp resp;

	if (global_shop == NULL) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		return;
	} else {
		resp.status = 0;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	}
	DBlistItems(global_shop->id);
	/* Maybe do smth in case of error */
}

void addItem(void) {
	StatusResp resp;
	ItemCreateReq req;
	Item item;
	char *name;
	
	if (global_shop == NULL) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		return;
	} else {
		resp.status = 0;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	}

	/*
	 * struct ItemCreateReq {
	 * 	uint64_t price;
	 * 	uint64_t amount;
	 * 	size_t name_len;
	 * 	//char name[];
	 * };
	*/
	checkRead(&req, sizeof(ItemCreateReq), 1, stdin);
	
	if ((name = calloc(1, req.name_len)) == NULL) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		perror("calloc");
		exitFunc(EXIT_FAILURE);
	} else {
		resp.status = 0;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	}

	checkRead(name, req.name_len, 1, stdin);

	item.id = rand();
	item.price = req.price;
	item.amount = req.amount;
	item.name = name;
	item.shop = global_shop;
	DBaddItem(&item);

	resp.status = item.id;
	checkWrite(&resp, sizeof(StatusResp), 1, stdout);

	free(name);
}


void buyItem(void) {
	StatusResp resp;
	uint64_t id;
	Item *dbItem;

	if (global_user == NULL || global_shop == NULL) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	} else {
		resp.status = 0;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
	}

	checkRead(&id, sizeof(uint64_t), 1, stdin);


	dbItem = DBgetItem(id);
	if (dbItem == NULL || global_shop->id != dbItem->shop->id) {
		resp.status = -1;
		checkWrite(&resp, sizeof(StatusResp), 1, stdout);
		return;
	}

	if (global_user->coins >= dbItem->price) {
		global_user->coins -= dbItem->price;
		global_shop->owner->coins += dbItem->price;
		resp.status = 0;
	} else {
		resp.status = -1;
	}
	checkWrite(&resp, sizeof(StatusResp), 1, stdout);
}

void mainLoop() {
	BaseReq req;
	while (1) {
		//checkRead(&req, 1, sizeof(uint64_t), stdin);
		checkRead(&req, 1, sizeof(BaseReq), stdin);
		switch (req.op) {
			case regU:
				regUser();
				break;
			case loginU:
				loginUser();
				break;
			case listS:
				listShops();
				break;
			case enterS:
				enterShop();
				break;
			case createS:
				createShop();
				break;
			case addI:
				addItem();
				break;
			case buyI:
				buyItem();
				break;
			case listI:
				listItems();
				break;
		}
	}
}

void setupFiles(void) {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
}


int main (void) {
	//User user;
	//Shop shop;
	//Item item;
	unsigned int seed;
	int fd;
	
	/* Setup seccomp */
	setupSeccomp();
	
	alarm(60);
	db_sleep.tv_nsec = 500;

	/* Set signal handling */
	signal(SIGTERM, dieFunc);
	signal(SIGUSR1, clearFunc);

	/* Init Files */
	setupFiles();

	/* Init random */
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		exitFunc(EXIT_FAILURE);
	}
	if (read(fd, &seed, sizeof(seed)) < 0) {
		exitFunc(EXIT_FAILURE);
	}
	close(fd);
	srand(seed);


	/* Create db */
	createDB();

	/* Start main loop */
	mainLoop();
	exitFunc(EXIT_FAILURE);
}
