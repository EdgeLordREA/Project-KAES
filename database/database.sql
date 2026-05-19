-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema nbuch
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema nbuch
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `nbuch` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci ;
USE `nbuch` ;

-- -----------------------------------------------------
-- Table `nbuch`.`categories`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nbuch`.`categories` (
  `category_id` INT NOT NULL,
  `name` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`category_id`),
  UNIQUE INDEX `name_UNIQUE` (`name` ASC) VISIBLE)
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `nbuch`.`permissions`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nbuch`.`permissions` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 2
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `nbuch`.`questions`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nbuch`.`questions` (
  `id` INT NOT NULL,
  `question` VARCHAR(255) NOT NULL,
  `category` INT NULL DEFAULT NULL,
  `modifier` INT NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  INDEX `category_idx` (`category` ASC) VISIBLE,
  CONSTRAINT `fk_questions_category`
    FOREIGN KEY (`category`)
    REFERENCES `nbuch`.`categories` (`category_id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `nbuch`.`users`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nbuch`.`users` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(32) NOT NULL,
  `password` VARCHAR(60) NOT NULL,
  `create_time` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `username_UNIQUE` (`username` ASC) VISIBLE)
ENGINE = InnoDB
AUTO_INCREMENT = 4
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `nbuch`.`userpermissions`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nbuch`.`userpermissions` (
  `user` INT NOT NULL,
  `permission` INT NOT NULL,
  PRIMARY KEY (`user`),
  INDEX `permission_idx` (`permission` ASC) VISIBLE,
  CONSTRAINT `fk_userpermissions_permission`
    FOREIGN KEY (`permission`)
    REFERENCES `nbuch`.`permissions` (`id`),
  CONSTRAINT `fk_userpermissions_users`
    FOREIGN KEY (`user`)
    REFERENCES `nbuch`.`users` (`id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8mb4
COLLATE = utf8mb4_0900_ai_ci;


-- -----------------------------------------------------
-- Table `nbuch`.`exams`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nbuch`.`exams` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `title` VARCHAR(45) NULL,
  PRIMARY KEY (`id`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `nbuch`.`examquestions`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nbuch`.`examquestions` (
  `examid` INT NOT NULL,
  `questionid` INT NOT NULL,
  `order` INT NOT NULL AUTO_INCREMENT,
  INDEX `fk_examquestions_question_idx` (`questionid` ASC) VISIBLE,
  CONSTRAINT `fk_examquestions_exam`
    FOREIGN KEY (`examid`)
    REFERENCES `nbuch`.`exams` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_examquestions_question`
    FOREIGN KEY (`questionid`)
    REFERENCES `nbuch`.`questions` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `nbuch`.`userexams`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nbuch`.`userexams` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `userid` INT NOT NULL,
  `examid` INT NOT NULL,
  `time_finished` TIMESTAMP NULL,
  `time_started` TIMESTAMP NULL,
  PRIMARY KEY (`id`),
  INDEX `fk_userexams_user_idx` (`userid` ASC) VISIBLE,
  INDEX `fk_userexams_exam_idx` (`examid` ASC) VISIBLE,
  CONSTRAINT `fk_userexams_user`
    FOREIGN KEY (`userid`)
    REFERENCES `nbuch`.`users` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_userexams_exam`
    FOREIGN KEY (`examid`)
    REFERENCES `nbuch`.`exams` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `nbuch`.`examanswers`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `nbuch`.`examanswers` (
  `userexamid` INT NOT NULL,
  `questionid` INT NOT NULL,
  `answer` INT NOT NULL,
  INDEX `fk_examanswers_exam_idx` (`userexamid` ASC) VISIBLE,
  INDEX `fk_examanswers_question_idx` (`questionid` ASC) VISIBLE,
  PRIMARY KEY (`userexamid`, `questionid`),
  CONSTRAINT `fk_examanswers_exam`
    FOREIGN KEY (`userexamid`)
    REFERENCES `nbuch`.`userexams` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_examanswers_question`
    FOREIGN KEY (`questionid`)
    REFERENCES `nbuch`.`questions` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
