/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { Inject, Injectable } from '@nestjs/common';
import * as Misskey from 'misskey-js';
import { DI } from '@/di-symbols.js';
import type { Config } from '@/config.js';
import type { SigninsRepository, UserProfilesRepository } from '@/models/_.js';
import { IdService } from '@/core/IdService.js';
import type { MiLocalUser } from '@/models/User.js';
import { GlobalEventService } from '@/core/GlobalEventService.js';
import { SigninEntityService } from '@/core/entities/SigninEntityService.js';
import { bindThis } from '@/decorators.js';
import { EmailService } from '@/core/EmailService.js';
import { NotificationService } from '@/core/NotificationService.js';
import type { FastifyRequest, FastifyReply } from 'fastify';

@Injectable()
export class SigninService {
	constructor(
		@Inject(DI.config)
		private config: Config,

		@Inject(DI.signinsRepository)
		private signinsRepository: SigninsRepository,

		@Inject(DI.userProfilesRepository)
		private userProfilesRepository: UserProfilesRepository,

		private signinEntityService: SigninEntityService,
		private emailService: EmailService,
		private notificationService: NotificationService,
		private idService: IdService,
		private globalEventService: GlobalEventService,
	) {
	}

	@bindThis
	public signin(request: FastifyRequest, reply: FastifyReply, user: MiLocalUser) {
		setImmediate(async () => {
			this.notificationService.createNotification(user.id, 'login', {});

			const record = await this.signinsRepository.insertOne({
				id: this.idService.gen(),
				userId: user.id,
				ip: request.ip,
				headers: request.headers as any,
				success: true,
			});

			this.globalEventService.publishMainStream(user.id, 'signin', await this.signinEntityService.pack(record));

			const profile = await this.userProfilesRepository.findOneByOrFail({ userId: user.id });
			if (profile.email && profile.emailVerified) {
				this.emailService.sendEmail(profile.email, `【${this.config.url}】新規ログインのお知らせ`,
					`${user.name??`@${user.username}`} 様<br><br>`+
					`いつも${this.config.url}をご利用いただきありがとうございます。<br><br>`+
					`お使いのアカウント(@${user.username})に対する新しいログインがありましたのでお知らせいたします。<br><br>`+
					`ログイン時刻 : ${new Date().toLocaleString('ja-JP', {timeZone: 'Asia/Tokyo',})}<br>`+
					`IPアドレス : ${request.ip}<br><br>`+
					`<strong>●ユーザー自身がログインした場合</strong><br>`+
					`このメールは無視して構いません。<br>`+
					`引き続き${this.config.url}をお楽しみください<br><br>`+
					`<strong>●このログインに心当たりがない場合</strong><br>`+
					`すぐにパスワードを変更とログイントークンを再生成し、アカウントを保護してください。<br><br>`+
					`また、パスワード変更やログイン履歴等の各種情報は以下のURLから確認できます。<br>`+
					`<a href="https://${this.config.url}/settings/security">https://${this.config.url}/settings/security</a><br><br>`+
					`※本メールは送信専用になります。`
					,
					`${user.name??`@${user.username}`} 様\n\n`+
					`いつも${this.config.url}をご利用いただきありがとうございます。\n\n`+
					`お使いのアカウント(@${user.username})に対する新しいログインがありましたのでお知らせいたします。\n\n`+
					`ログイン時刻 : ${new Date().toLocaleString('ja-JP', {timeZone: 'Asia/Tokyo',})}\n`+
					`IPアドレス : ${request.ip}\n\n`+
					`●ユーザー自身がログインした場合\n`+
					`このメールは無視して構いません。\n`+
					`引き続き${this.config.url}をお楽しみください\n\n`+
					`●このログインに心当たりがない場合\n`+
					`すぐにパスワードを変更とログイントークンを再生成し、アカウントを保護してください。\n\n`+
					`また、パスワード変更やログイン履歴等の各種情報は以下のURLから確認できます。\n`+
					`https://${this.config.url}/settings/security \n\n`+
					`※本メールは送信専用になります。`);
			}
		});

		reply.code(200);
		return {
			finished: true,
			id: user.id,
			i: user.token!,
		} satisfies Misskey.entities.SigninFlowResponse;
	}
}

