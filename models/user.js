/** User class for message.ly */

const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR } = require("../config");

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    let hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

    const response = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at) VALUES($1, $2, $3, $4, $5, current_timestamp,current_timestamp) RETURNING username, password, first_name, last_name, phone`[
        (username, hashedPassword, first_name, last_name, phone)
      ]
    );

    return response.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT password FROM users where username = $1`,
      [username]
    );
    const user = result.rows[0];

    return user && (await bcrypt.compare(password, user.password));
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users SET last_login_at = current_timestamp WHERE username = $1 RETURNING username`,
      [username]
    );

    if (!result.rows[0]) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone FROM users ORDER BY username`
    );

    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users WHERE username = $1`,
      [username]
    );

    const user = result.rows[0];

    if (!user) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }

    return user;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `select m.id,
      m.to_username,
      u.first_name,
      u.last_name,
      u.phone,
      m.body, 
      m.sent_at,
      m.read_at 
      from messages as m
      join users as u on m.to_username = u.username where from_username = $1`,
      [username]
    );

    return result.rows.map((message) => ({
      id: message.id,
      to_user: {
        username: message.to_username,
        first_name: message.first_name,
        last_name: message.last_name,
        phone: message.phone,
      },
      body: message.body,
      sent_at: message.sent_at,
      read_at: message.read_at,
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const result = await db.query(
      `select m.id,
      m.from_username,
      u.first_name,
      u.last_name,
      u.phone,
      m.body, 
      m.sent_at,
      m.read_at 
      from messages as m
      join users as u on m.from_username = u.username where to_username = $1`,
      [username]
    );

    return result.rows.map((message) => ({
      id: message.id,
      from_user: {
        username: message.from_username,
        first_name: message.first_name,
        last_name: message.last_name,
        phone: message.phone,
      },
      body: message.body,
      sent_at: message.sent_at,
      read_at: message.read_at,
    }));
  }
}

module.exports = User;
