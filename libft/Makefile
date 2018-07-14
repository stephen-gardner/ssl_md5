#!/usr/bin/make -f

################################################################################
# SETTINGS                                                                     #
################################################################################

NAME = libft.a
CC = gcc
CFLAGS += -Wall -Werror -Wextra
CFLAGS += -Ofast -funroll-loops
CFLAGS += #-g -fsanitize=address
INC = -I inc
SRC_DIR = src
OBJ_DIR = obj

SRC = \
	ft_memalloc\
	ft_memcpy\
	ft_memset\
	ft_stpncpy\
	ft_strchr\
	ft_strcmp\
	ft_strdup\
	ft_strlen\
	ft_strnlen\
	ft_strupcase

# [ PRINTF ]

SRC += \
	printf/conv_char\
	printf/conv_float\
	printf/conv_int\
	printf/conv_int_deprecated\
	printf/conv_misc\
	printf/conv_wchar\
	printf/ft_printf\
	printf/parser\
	printf/process\
	printf/util\
	printf/util_int

# [ MEMORY MANAGER ]

SRC += \
	memmgr/ft_mchain\
	memmgr/ft_mladd\
	memmgr/ft_mlalloc\
	memmgr/ft_mlpop\
	memmgr/ft_mlrev

# [ OTHER ]

SRC += \
	getopt/ft_getopt

OBJ = $(patsubst %, $(OBJ_DIR)/%.o, $(SRC))

################################################################################
# COLORS                                                                       #
################################################################################

COLSIZE = 50
NC = \033[0m
GREEN = \033[1;32m
RED = \033[1;31m
YELLOW = \033[1;33m

################################################################################
# RULES                                                                        #
################################################################################

all: $(NAME)

$(NAME): $(OBJ)
	@ar -rcs $@ $(OBJ)
	@echo "$(GREEN)DONE$(NC)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(INC) -c $< -o $@

clean:
	@rm -rf $(OBJ_DIR)

fclean: clean
	@rm -f $(NAME)
	@echo "$(RED)$(NAME) removed$(NC)"

re: fclean all
