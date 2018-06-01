#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <seccomp.h>

#include "networking.h"
#include "shops.h"

#define UNUSED(x) (void)(x)
#define ERROR_MSG "Error occured\n"

static char *menu = "0. Register\n1. Login\n2. List shops\n3. Enter shop\n4. Create shop\n5. Add item\n6. Buy item\n7. List items\n8. Leave\nChoice: ";
static int shop_in[2];
static int shop_out[2];
static FILE *shop_con[2];


static char signature[0x200];

static pid_t childpid;

void exitFunc (int status) {
	puts(signature);
	kill(childpid, SIGUSR1);
	kill(childpid, SIGTERM);
	exit(status);
}

void setupSeccomp(void) {
	scmp_filter_ctx filter;

	if ((filter = seccomp_init(SCMP_ACT_KILL)) == NULL) {
	//if ((filter = seccomp_init(SCMP_ACT_LOG)) == NULL) {
		exitFunc(EXIT_FAILURE);
	}
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(time), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
	seccomp_rule_add_exact(filter, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0);
	if (seccomp_load(filter) < 0){
		exitFunc(EXIT_FAILURE);
	}
	seccomp_release(filter);
}

void *checkCalloc (size_t nmemb, size_t size) {
	void *ret;
	if ((ret = calloc(nmemb, size)) == NULL) {
		perror("calloc");
		exitFunc(EXIT_FAILURE);
	}
	return ret;
}

int64_t checkStatus (ConHandle *con) {
	StatusResp resp;

	resp.status = 0;
	checkRead(&resp, 1, sizeof(StatusResp), shop_con[0]);
	if (resp.status < 0) {
		con->sendMsg(con, ERROR_MSG);
		return -1;
	} else {
		return resp.status;
	}
}


void setupFiles (void) {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
}

void setup (void) {
	char *argv[] = {"./shops", 0};

	if (pipe(shop_in) == -1) {
		perror("pipe");
		exitFunc(EXIT_FAILURE);
	}

	if (pipe(shop_out) == -1) {
		perror("pipe");
		exitFunc(EXIT_FAILURE);
	}



	if ((childpid = fork()) == -1) {
		perror("fork");
		exitFunc(EXIT_FAILURE);
	}

	if (childpid == 0) {
			/* Start shop backend */
			dup2(shop_out[0], STDIN_FILENO);
			dup2(shop_in[1], STDOUT_FILENO);
			close(shop_out[1]);
			close(shop_in[0]);
			execve(argv[0], argv, NULL);
			perror("execve");
			exitFunc(EXIT_FAILURE);
	} else {
		shop_con[0] = fdopen(shop_in[0], "r");
		shop_con[1] = fdopen(shop_out[1], "w");
		if (shop_con[0] == NULL || shop_con[1] == NULL) {
			perror("fdopen");
			exitFunc(EXIT_FAILURE);
		}
		setvbuf(shop_con[0], NULL, _IONBF, 0);
		setvbuf(shop_con[1], NULL, _IONBF, 0);
		close(shop_in[1]);
		close(shop_out[0]);
	}
}

/*
 * enum Operation {regU = 0, loginU = 1, listS = 2, enterS = 3, createS = 4, addI = 5, removeI = 6, buyI = 7};
 * 
 * struct ShopMsg {
 * 	enum Operation op;
 * 	uint64_t payload_len;
 * 	unsigned char payload[];
 * };
 */

void regUser(ConHandle *con) {
	unsigned char *pwd;
	BaseReq req;
	int64_t status;
	char *ret_msg;
	size_t pwd_len;

	req.op = regU;
	checkWrite(&req, 1, sizeof(BaseReq), shop_con[1]);


	con->sendMsg(con, "User pwd: ");	
	pwd = con->recvMsg(con, &pwd_len);
	if (pwd == NULL || pwd_len <= 0 || pwd_len > 50) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	checkWrite(&pwd_len, 1, sizeof(pwd_len), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	checkWrite(pwd, 1, pwd_len, shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	if (asprintf(&ret_msg, "Registered user with id %ld\n", status) < 0) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	con->sendMsg(con, ret_msg);

	free(pwd);
	free(ret_msg);
}

void loginUser(ConHandle *con) {
	unsigned char *pwd, *id_str;
	BaseReq req;
	int64_t status;
	uint64_t user_id;
	char *ret_msg;
	size_t pwd_len, id_len;

	req.op = loginU;
	checkWrite(&req, 1, sizeof(BaseReq), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	con->sendMsg(con, "User id: ");	
	id_str = con->recvMsg(con, &id_len);
	user_id = atol((char *) id_str);
	checkWrite(&user_id, 1, sizeof(user_id), shop_con[1]);


	con->sendMsg(con, "User pwd: ");	
	pwd = con->recvMsg(con, &pwd_len);
	if (pwd == NULL || pwd_len <= 0 || pwd_len > 50) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	checkWrite(&pwd_len, 1, sizeof(pwd_len), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	checkWrite(pwd, 1, pwd_len, shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	if (asprintf(&ret_msg, "Successfully logged in user %ld\n", user_id) < 0) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	con->sendMsg(con, ret_msg);

	free(pwd);
	free(ret_msg);
}

void listShops(ConHandle *con) {
	BaseReq req;
	int64_t id;
	size_t name_len;
	char *msg;
	char *name;

	req.op = listS;
	checkWrite(&req, 1, sizeof(BaseReq), shop_con[1]);

	
	/*
	 * struct ListResp {
	 * 	int64_t id;
	 * 	size_t name_len;
	 * 	char name[];
	 * };
	 */
	checkRead(&id, 1, sizeof(int64_t), shop_con[0]);
	name_len = 0;
	while (id > 0) {
		checkRead(&name_len, sizeof(size_t), 1, shop_con[0]);
		name = checkCalloc(1, name_len+1);
		checkRead(name, name_len+1, 1, shop_con[0]);
		// VULN: Forget to account for the ID size field
		if (asprintf(&msg, "ID: %lu - NAME: %s", id, name) == -1) {
			perror("asprintf");
			exitFunc(EXIT_FAILURE);
		}
		con->sendMsg(con, msg);
		free(msg);
		checkRead(&id, 1, sizeof(int64_t), shop_con[0]);
	}
}

void enterShop(ConHandle *con) {
	unsigned char *pwd, *id_str;
	BaseReq req;
	int64_t status;
	uint64_t user_id;
	char *ret_msg;
	size_t pwd_len, id_len;

	req.op = enterS;
	checkWrite(&req, 1, sizeof(BaseReq), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	con->sendMsg(con, "Shop id: ");	
	id_str = con->recvMsg(con, &id_len);
	user_id = atol((char *) id_str);
	checkWrite(&user_id, 1, sizeof(user_id), shop_con[1]);


	con->sendMsg(con, "Shop pwd: ");	
	pwd = con->recvMsg(con, &pwd_len);
	if (pwd == NULL || pwd_len <= 0 || pwd_len > 50) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	checkWrite(&pwd_len, 1, sizeof(pwd_len), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	checkWrite(pwd, 1, pwd_len, shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	if (asprintf(&ret_msg, "Successfully entered shop %ld\n", user_id) < 0) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	con->sendMsg(con, ret_msg);

	free(pwd);
	free(ret_msg);
}

void createShop(ConHandle *con) {
	/*
	 * struct ShopCreateReq {
	 *  	size_t name_len;
	 *  	size_t pwd_len;
	 * };
	 */
	unsigned char *name;
	unsigned char *pwd;
	BaseReq req;
	ShopCreateReq createReq;
	int64_t status;
	char *ret_msg;
	size_t name_len, pwd_len;

	req.op = createS;
	checkWrite(&req, 1, sizeof(BaseReq), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	con->sendMsg(con, "Shop name: ");	
	name = con->recvMsg(con, &name_len);
	if (name == NULL || name_len < 20 || name_len > 40) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	con->sendMsg(con, "Shop pwd: ");	
	pwd = con->recvMsg(con, &pwd_len);
	if (pwd == NULL || pwd_len <= 0 || pwd_len > 20) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	createReq.name_len = name_len;
	createReq.pwd_len = pwd_len;
	checkWrite(&createReq, 1, sizeof(ShopCreateReq), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	checkWrite(name, 1, name_len, shop_con[1]);
	checkWrite(pwd, 1, pwd_len, shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	if (asprintf(&ret_msg, "Created shop with id %ld\n", status) < 0) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	con->sendMsg(con, ret_msg);

	free(name);
	free(pwd);
	free(ret_msg);
}

void addItem(ConHandle *con) {
	/*
	 * struct ItemCreateReq {
	 * 	uint64_t price;
	 * 	uint64_t amount;
	 * 	size_t name_len;
	 * 	//char name[];
	 * };
	 */
	unsigned char *name;
	uint64_t name_len;
	BaseReq req;
	int64_t status;
	char *ret_msg;
	unsigned char *msg;
	size_t len;
	ItemCreateReq createReq;

	req.op = addI;
	checkWrite(&req, 1, sizeof(BaseReq), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	con->sendMsg(con, "Item price: ");	
	msg = con->recvMsg(con, &len);
	createReq.price = atol((char *) msg);

	con->sendMsg(con, "Item amount: ");	
	msg = con->recvMsg(con, &len);
	createReq.amount = atol((char *) msg);

	con->sendMsg(con, "Item name: ");	
	name = con->recvMsg(con, &name_len);
	if (name == NULL || name_len <= 0 || strlen((char *) name) > 50) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	memcpy(createReq.name, name, name_len);
	createReq.name_len = name_len;
	checkWrite(&createReq, 1, sizeof(ItemCreateReq), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	checkWrite(name, 1, name_len, shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	if (asprintf(&ret_msg, "Created item with id %ld\n", status) < 0) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	con->sendMsg(con, ret_msg);

	free(name);
	free(ret_msg);
}

void listItems(ConHandle *con) {
	BaseReq req;
	int64_t id, status;
	size_t name_len;
	char *name;
	char *msg;

	req.op = listI;
	checkWrite(&req, 1, sizeof(BaseReq), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}
	
	/*
	 * struct ListResp {
	 * 	int64_t id;
	 * 	size_t name_len;
	 * 	char name[];
	 * };
	 */
	checkRead(&id, 1, sizeof(int64_t), shop_con[0]);
	while (id > 0) {
		checkRead(&name_len, sizeof(size_t), 1, shop_con[0]);
		name = checkCalloc(1, name_len+1);
		checkRead(name, name_len+1, 1, shop_con[0]);
		if (asprintf(&msg, "ID: %lu - NAME: %s", id, name) == -1) {
			perror("asprintf");
			exitFunc(EXIT_FAILURE);
		}
		con->sendMsg(con, msg);
		free(msg);
		checkRead(&id, 1, sizeof(int64_t), shop_con[0]);
	}
}

void buyItem(ConHandle *con) {
	BaseReq req;
	uint64_t id;
	int64_t status;
		char *ret_msg;
	unsigned char *msg;
	size_t len;

	req.op = buyI;
	checkWrite(&req, 1, sizeof(BaseReq), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	con->sendMsg(con, "Item id: ");	
	msg = con->recvMsg(con, &len);
	id = atol((char *) msg);

	checkWrite(&id, 1, sizeof(uint64_t), shop_con[1]);
	status = 0;
	if ((status = checkStatus(con)) < 0) {
		return;
	}

	if (asprintf(&ret_msg, "Bought item with id %ld\n", status) < 0) {
		con->sendMsg(con, ERROR_MSG);
		return;
	}
	con->sendMsg(con, ret_msg);

	free(ret_msg);
}

int main(void) {
	ConHandle *con;
	unsigned char *resp, *msg;
	size_t resp_len;
	int choice;
	size_t len;

	setupFiles();
	setup();
	setupSeccomp();

	alarm(60);

	if ((con = createCon(stdin, stdout)) == NULL) {
		exitFunc(EXIT_FAILURE);
	}
	if (initSession(con) != EXIT_SUCCESS) {
		exitFunc(EXIT_FAILURE);
	}

	con->sendMsg(con, "Welcome to Diagon Alley, stranger!");
	con->sendMsg(con, "Do you want to set a signature? (y/N)");
	msg = con->recvMsg(con, &len);
	if (msg[0] == 'y') {
		con->sendMsg(con, "Ok enter your signature:");
		msg = con->recvMsg(con, &len);
		memcpy(signature, msg, 0x200);
	}

	while (1) {
		con->sendMsg(con, menu);
		resp = con->recvMsg(con, &resp_len);
		if (resp == NULL) {
			exitFunc(EXIT_FAILURE);
		}
		choice = atoi((char *) resp);
		switch (choice) {
			case 0:
				regUser(con);
				break;
			case 1:
				loginUser(con);
				break;
			case 2:
				listShops(con);
				break;
			case 3:
				enterShop(con);
				break;
			case 4:
				createShop(con);
				break;
			case 5:
				addItem(con);
				break;
			case 6:
				buyItem(con);
				break;
			case 7:
				listItems(con);
				break;
			case 8:
				return EXIT_SUCCESS;
		}
	}

	return EXIT_SUCCESS;
}
