#ifndef SHOPS_H
#define SHOPS_H

#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

enum Operation {regU = 0, loginU = 1, listS = 2, enterS = 3, createS = 4, addI = 5, buyI = 6, listI = 7};

struct Item;
typedef struct Item Item;
struct Shop;
typedef struct Shop Shop;

struct User {
	uint64_t id;
	char *pwd;
	uint64_t coins;
};
typedef struct User User;

struct Item {
	uint64_t id;
	uint64_t price;
	uint64_t amount;
	Shop *shop;
	char *name;
};

struct Shop {
	uint64_t id;
	char *name;
	char *pwd;
	User *owner;
};


struct BaseReq {
	//enum Operation op;
	uint64_t op;
};
typedef struct BaseReq BaseReq;

struct ShopCreateReq {
	size_t name_len;
	size_t pwd_len;
	//char payload[];
	//char name[];
	//char pwd[];
};
typedef struct ShopCreateReq ShopCreateReq;

struct ItemCreateReq {
	uint64_t price;
	uint64_t amount;
	size_t name_len;
	char name[40];
};
typedef struct ItemCreateReq ItemCreateReq;


struct ShopResp {
	uint64_t status;
	ssize_t payload_len;
	char *payload;
};
typedef struct ShopResp ShopResp;

struct StatusResp {
	int64_t status;
};
typedef struct StatusResp StatusResp;

struct ListResp {
	int64_t id;
	size_t name_len;
	char name[];
};
typedef struct ListResp ListResp;




#endif
